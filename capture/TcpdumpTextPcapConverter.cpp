#include "TcpdumpTextPcapConverter.h"
#include "PcapTypes.h"

#include <QDateTime>
#include <QRegularExpression>
#include <QTime>
#include <limits>

namespace {

struct TextPacket {
    QDate date;
    QTime time;
    int microseconds = 0;
    QByteArray frame;
    bool offsetGap = false;
};

void appendLe16(QByteArray& out, quint16 value){
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

void appendLe32(QByteArray& out, quint32 value){
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
    out.append(char((value >> 16) & 0xff));
    out.append(char((value >> 24) & 0xff));
}

quint16 readBe16(const QByteArray& data, int offset){
    if(offset < 0 || offset + 1 >= data.size()) return 0;
    const auto* p = reinterpret_cast<const unsigned char*>(data.constData() + offset);
    return quint16((quint16(p[0]) << 8) | quint16(p[1]));
}

bool isVlanEtherType(quint16 type){
    return type == 0x8100 || type == 0x88a8 || type == 0x9100;
}

quint32 detectLinkType(const QByteArray& frame){
    // Linux cooked capture v2 (used by newer tcpdump -i any): protocol,reserved,ifindex,hatype,pkttype,halen,address.
    if(frame.size() >= 20){
        const quint16 protocol=readBe16(frame,0);
        const quint16 reserved=readBe16(frame,2);
        const quint8 halen=quint8(frame.at(11));
        if((protocol==0x0800||protocol==0x86dd||protocol==0x0806) && reserved==0 && halen<=8)
            return PcapLinkType::LinuxSll2;
    }
    // Linux cooked capture v1.
    if(frame.size() >= 16){
        const quint16 packetType=readBe16(frame,0);
        const quint16 halen=readBe16(frame,4);
        const quint16 protocol=readBe16(frame,14);
        if(packetType<=4 && halen<=8 && (protocol==0x0800||protocol==0x86dd||protocol==0x0806))
            return PcapLinkType::LinuxSll;
    }
    if(frame.size() >= 14){
        const quint16 etherType = readBe16(frame,12);
        if(etherType == 0x0800 || etherType == 0x86dd || etherType == 0x0806 || isVlanEtherType(etherType))
            return PcapLinkType::Ethernet;
    }
    if(!frame.isEmpty()){
        const quint8 version = quint8(frame.at(0)) >> 4;
        if(version == 4 || version == 6) return PcapLinkType::Raw;
    }
    return 0;
}

int ipOffset(const QByteArray& frame, quint32 linkType){
    if(linkType == PcapLinkType::Raw) return 0;
    if(linkType == PcapLinkType::LinuxSll){
        if(frame.size()<16)return -1;
        const quint16 protocol=readBe16(frame,14);
        return (protocol==0x0800||protocol==0x86dd)?16:-1;
    }
    if(linkType == PcapLinkType::LinuxSll2){
        if(frame.size()<20)return -1;
        const quint16 protocol=readBe16(frame,0);
        return (protocol==0x0800||protocol==0x86dd)?20:-1;
    }
    if(linkType != PcapLinkType::Ethernet || frame.size() < 14) return -1;

    int payloadOffset = 14;
    quint16 etherType = readBe16(frame,12);
    while(isVlanEtherType(etherType)){
        if(frame.size() < payloadOffset + 4) return -1;
        etherType = readBe16(frame,payloadOffset + 2);
        payloadOffset += 4;
    }
    if(etherType != 0x0800 && etherType != 0x86dd) return -1;
    return payloadOffset;
}

int expectedMinimumLength(const QByteArray& frame, quint32 linkType){
    const int offset = ipOffset(frame,linkType);
    if(offset < 0 || frame.size() <= offset) return 0;
    const quint8 version = quint8(frame.at(offset)) >> 4;
    if(version == 4){
        if(frame.size() < offset + 4) return 0;
        const quint16 totalLength = readBe16(frame,offset + 2);
        return totalLength >= 20 ? offset + int(totalLength) : 0;
    }
    if(version == 6){
        if(frame.size() < offset + 6) return 0;
        const quint16 payloadLength = readBe16(frame,offset + 4);
        return offset + 40 + int(payloadLength);
    }
    return 0;
}

QByteArray parseHexWords(const QString& text){
    QByteArray bytes;
    const QStringList tokens = text.split(QRegularExpression(QStringLiteral("\\s+")),Qt::SkipEmptyParts);
    static const QRegularExpression word4(QStringLiteral("^[0-9A-Fa-f]{4}$"));
    static const QRegularExpression word2(QStringLiteral("^[0-9A-Fa-f]{2}$"));
    for(const QString& token: tokens){
        if(word4.match(token).hasMatch() || word2.match(token).hasMatch())
            bytes.append(QByteArray::fromHex(token.toLatin1()));
        else
            break;
    }
    return bytes;
}

}

bool TcpdumpTextPcapConverter::convert(const QByteArray& textBytes,
                                       TcpdumpTextConversionResult* result,
                                       QString* error,
                                       const QDate& fallbackDate){
    if(error) error->clear();
    if(!result){
        if(error) *error = QStringLiteral("转换结果对象为空");
        return false;
    }
    *result = TcpdumpTextConversionResult{};

    const QString text = QString::fromLatin1(textBytes);
    const QStringList lines = text.split(QRegularExpression(QStringLiteral("\\r?\\n")));

    static const QRegularExpression dateRe(QStringLiteral("(?:PuTTY\\s+log\\s+)?(\\d{4})[./-](\\d{1,2})[./-](\\d{1,2})"),QRegularExpression::CaseInsensitiveOption);
    QDate baseDate;
    const auto dateMatch = dateRe.match(text);
    if(dateMatch.hasMatch()){
        baseDate = QDate(dateMatch.captured(1).toInt(),dateMatch.captured(2).toInt(),dateMatch.captured(3).toInt());
    }
    if(!baseDate.isValid()){
        baseDate = fallbackDate.isValid() ? fallbackDate : QDate::currentDate();
        result->warnings << QStringLiteral("日志中未找到日期，PCAP 日期使用 %1").arg(baseDate.toString(Qt::ISODate));
    }
    result->sourceDate = baseDate;

    static const QRegularExpression packetRe(QStringLiteral("^(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{1,6})\\s+(?:(?:[^\\s]+)\\s+(?:In|Out)\\s+)?(?:IP6?|ip6?)\\b"));
    static const QRegularExpression hexRe(QStringLiteral("^\\s*0x([0-9A-Fa-f]+):\\s*(.*)$"));

    QList<TextPacket> packets;
    TextPacket current;
    bool haveCurrent = false;
    QDate runningDate = baseDate;
    QTime previousTime;

    auto finishCurrent = [&](){
        if(haveCurrent){
            packets.append(current);
            current = TextPacket{};
            haveCurrent = false;
        }
    };

    for(const QString& line: lines){
        const auto packetMatch = packetRe.match(line);
        if(packetMatch.hasMatch()){
            finishCurrent();
            const int usec = packetMatch.captured(4).leftJustified(6,QChar('0')).toInt();
            const QTime time(packetMatch.captured(1).toInt(),packetMatch.captured(2).toInt(),packetMatch.captured(3).toInt(),usec/1000);
            if(previousTime.isValid() && time.isValid() && previousTime.secsTo(time) < -12*60*60)
                runningDate = runningDate.addDays(1);
            previousTime = time;
            current.date = runningDate;
            current.time = time;
            current.microseconds = usec;
            haveCurrent = true;
            continue;
        }

        if(!haveCurrent) continue;
        const auto hexMatch = hexRe.match(line);
        if(!hexMatch.hasMatch()) continue;
        bool ok = false;
        const int offset = hexMatch.captured(1).toInt(&ok,16);
        const QByteArray chunk = parseHexWords(hexMatch.captured(2));
        if(!ok || chunk.isEmpty()) continue;
        if(offset != current.frame.size()) current.offsetGap = true;
        if(offset == current.frame.size()) current.frame.append(chunk);
    }
    finishCurrent();

    struct AcceptedPacket { TextPacket packet; quint32 linkType = 0; };
    QList<AcceptedPacket> accepted;
    quint32 streamLinkType = 0;

    for(const TextPacket& packet: packets){
        if(packet.frame.isEmpty()){
            result->skippedPacketCount++;
            continue;
        }
        const quint32 linkType = detectLinkType(packet.frame);
        if(linkType == 0){
            result->skippedPacketCount++;
            result->warnings << QStringLiteral("跳过一个无法识别链路类型的数据包");
            continue;
        }
        if(streamLinkType == 0) streamLinkType = linkType;
        if(linkType != streamLinkType){
            result->skippedPacketCount++;
            result->warnings << QStringLiteral("日志中混合了不同链路类型，已跳过不一致的数据包");
            continue;
        }
        const int minimum = expectedMinimumLength(packet.frame,linkType);
        if(packet.offsetGap || (minimum > 0 && packet.frame.size() < minimum)){
            result->truncatedPacketCount++;
            continue;
        }
        accepted.append({packet,linkType});
    }

    if(accepted.isEmpty()){
        if(result->truncatedPacketCount > 0)
            result->warnings << QStringLiteral("检测到 %1 个十六进制不完整的数据包，缺失字节无法恢复").arg(result->truncatedPacketCount);
        if(error) *error = QStringLiteral("未找到可完整恢复为 PCAP 的数据包");
        return false;
    }

    if(result->truncatedPacketCount > 0)
        result->warnings << QStringLiteral("部分恢复：%1 个数据包十六进制内容不完整，已跳过且未伪造缺失字节").arg(result->truncatedPacketCount);
    if(result->skippedPacketCount > 0)
        result->warnings << QStringLiteral("另有 %1 个数据包无法恢复，已跳过").arg(result->skippedPacketCount);

    result->linkType = streamLinkType;
    QByteArray pcap;
    appendLe32(pcap,0xa1b2c3d4u);
    appendLe16(pcap,2);
    appendLe16(pcap,4);
    appendLe32(pcap,0);
    appendLe32(pcap,0);
    appendLe32(pcap,65535);
    appendLe32(pcap,streamLinkType);

    for(const AcceptedPacket& acceptedPacket: accepted){
        const TextPacket& packet = acceptedPacket.packet;
        const QDateTime timestamp(packet.date,packet.time,Qt::LocalTime);
        const qint64 seconds = timestamp.toSecsSinceEpoch();
        if(seconds < 0 || seconds > qint64(std::numeric_limits<quint32>::max())){
            result->skippedPacketCount++;
            continue;
        }
        appendLe32(pcap,quint32(seconds));
        appendLe32(pcap,quint32(packet.microseconds));
        appendLe32(pcap,quint32(packet.frame.size()));
        appendLe32(pcap,quint32(packet.frame.size()));
        pcap.append(packet.frame);
        result->packetCount++;
    }

    if(result->packetCount == 0){
        if(error) *error = QStringLiteral("数据包时间戳超出 Classic PCAP 可表示范围");
        return false;
    }
    result->pcapData = pcap;
    return true;
}
