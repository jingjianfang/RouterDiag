#include "TcpdumpTextStreamParser.h"
#include "PcapTypes.h"

#include <QDateTime>
#include <QRegularExpression>
#include <limits>

namespace {
void appendLe16(QByteArray& out,quint16 v){out.append(char(v&0xff));out.append(char((v>>8)&0xff));}
void appendLe32(QByteArray& out,quint32 v){out.append(char(v&0xff));out.append(char((v>>8)&0xff));out.append(char((v>>16)&0xff));out.append(char((v>>24)&0xff));}
quint16 readBe16(const QByteArray& d,int o){if(o<0||o+1>=d.size())return 0;const auto*p=reinterpret_cast<const uchar*>(d.constData()+o);return quint16((quint16(p[0])<<8)|p[1]);}
bool vlan(quint16 t){return t==0x8100||t==0x88a8||t==0x9100;}
quint32 linkTypeFor(const QByteArray& frame){
    // Linux cooked capture v2: protocol is the first 16 bits and reserved field is zero.
    if(frame.size()>=20){const quint16 proto=readBe16(frame,0);const quint16 reserved=readBe16(frame,2);const quint8 packetType=quint8(frame.at(10));const quint8 halen=quint8(frame.at(11));
        if((proto==0x0800||proto==0x86dd||proto==0x0806) && reserved==0 && packetType<=4 && halen<=8)return PcapLinkType::LinuxSll2;}
    if(frame.size()>=16){const quint16 packetType=readBe16(frame,0);const quint16 halen=readBe16(frame,4);const quint16 proto=readBe16(frame,14);
        if(packetType<=4 && halen<=8 && (proto==0x0800||proto==0x86dd||proto==0x0806))return PcapLinkType::LinuxSll;}
    if(frame.size()>=14){const quint16 t=readBe16(frame,12);if(t==0x0800||t==0x86dd||t==0x0806||vlan(t))return PcapLinkType::Ethernet;}
    if(!frame.isEmpty()){const quint8 v=quint8(frame.at(0))>>4;if(v==4||v==6)return PcapLinkType::Raw;}
    return 0;
}
int ipOffset(const QByteArray& f,quint32 link){
    if(link==PcapLinkType::Raw)return 0;
    if(link==PcapLinkType::LinuxSll){if(f.size()<16)return -1;return (readBe16(f,14)==0x0800||readBe16(f,14)==0x86dd)?16:-1;}
    if(link==PcapLinkType::LinuxSll2){if(f.size()<20)return -1;return (readBe16(f,0)==0x0800||readBe16(f,0)==0x86dd)?20:-1;}
    if(link!=PcapLinkType::Ethernet||f.size()<14)return -1;
    int off=14;quint16 t=readBe16(f,12);
    while(vlan(t)){if(f.size()<off+4)return -1;t=readBe16(f,off+2);off+=4;}
    return (t==0x0800||t==0x86dd)?off:-1;
}
int expectedLength(const QByteArray& f,quint32 link){
    const int off=ipOffset(f,link);if(off<0||f.size()<=off)return 0;
    const quint8 v=quint8(f.at(off))>>4;
    if(v==4){if(f.size()<off+4)return 0;const quint16 n=readBe16(f,off+2);return n>=20?off+int(n):0;}
    if(v==6){if(f.size()<off+6)return 0;return off+40+int(readBe16(f,off+4));}
    return 0;
}
QByteArray parseWords(const QString& value){
    QByteArray bytes;
    const QStringList tokens=value.split(QRegularExpression(QStringLiteral("\\s+")),Qt::SkipEmptyParts);
    static const QRegularExpression w4(QStringLiteral("^[0-9A-Fa-f]{4}$"));
    static const QRegularExpression w2(QStringLiteral("^[0-9A-Fa-f]{2}$"));
    for(const QString& token:tokens){if(w4.match(token).hasMatch()||w2.match(token).hasMatch())bytes.append(QByteArray::fromHex(token.toLatin1()));else break;}
    return bytes;
}
QByteArray globalHeader(quint32 link){QByteArray o;appendLe32(o,0xa1b2c3d4u);appendLe16(o,2);appendLe16(o,4);appendLe32(o,0);appendLe32(o,0);appendLe32(o,65535);appendLe32(o,link);return o;}
}

void TcpdumpTextStreamParser::reset(const QDate& fallbackDate)
{
    m_lineBuffer.clear();m_date=fallbackDate.isValid()?fallbackDate:QDate::currentDate();m_previousTime=QTime();m_currentTime=QTime();
    m_currentUsec=0;m_frame.clear();m_haveCurrent=false;m_offsetGap=false;m_linkType=0;m_headerWritten=false;m_packetCount=0;m_skippedPacketCount=0;
}

QByteArray TcpdumpTextStreamParser::feed(const QByteArray& chunk)
{
    QByteArray out;
    m_lineBuffer+=chunk;
    while(true){
        const int nl=m_lineBuffer.indexOf('\n');
        if(nl<0)break;
        QByteArray line=m_lineBuffer.left(nl);m_lineBuffer.remove(0,nl+1);
        if(!line.isEmpty()&&line.endsWith('\r'))line.chop(1);
        out+=processLine(QString::fromLocal8Bit(line));
    }
    return out;
}

QByteArray TcpdumpTextStreamParser::processLine(const QString& line)
{
    QByteArray out;
    static const QRegularExpression packetRe(QStringLiteral("^(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{1,6})\\s+(?:(?:[^\\s]+)\\s+(?:In|Out)\\s+)?(?:IP6?|ip6?)\\b"));
    static const QRegularExpression hexRe(QStringLiteral("^\\s*0x([0-9A-Fa-f]+):\\s*(.*)$"));
    const auto packet=packetRe.match(line);
    if(packet.hasMatch()){
        out+=finishCurrent(true);
        const int usec=packet.captured(4).leftJustified(6,QChar('0')).toInt();
        const QTime time(packet.captured(1).toInt(),packet.captured(2).toInt(),packet.captured(3).toInt(),usec/1000);
        if(m_previousTime.isValid()&&time.isValid()&&m_previousTime.secsTo(time)<-12*60*60)m_date=m_date.addDays(1);
        m_previousTime=time;m_currentTime=time;m_currentUsec=usec;m_frame.clear();m_offsetGap=false;m_haveCurrent=true;
        return out;
    }
    if(!m_haveCurrent)return out;
    const auto hex=hexRe.match(line);
    if(!hex.hasMatch())return out;
    bool ok=false;const int offset=hex.captured(1).toInt(&ok,16);const QByteArray bytes=parseWords(hex.captured(2));
    if(!ok||bytes.isEmpty())return out;
    if(offset!=m_frame.size())m_offsetGap=true;
    if(offset==m_frame.size())m_frame+=bytes;
    const quint32 link=linkTypeFor(m_frame);
    const int expected=link?expectedLength(m_frame,link):0;
    // Once a full IP packet is present, tcpdump -xx has provided enough data to parse it.
    // Finalize now instead of waiting for Stop, giving the UI live rows.
    if(expected>0&&m_frame.size()>=expected)out+=finishCurrent(false);
    return out;
}

QByteArray TcpdumpTextStreamParser::finishCurrent(bool force)
{
    Q_UNUSED(force)
    if(!m_haveCurrent)return {};
    QByteArray out;
    const quint32 link=linkTypeFor(m_frame);
    const int expected=link?expectedLength(m_frame,link):0;
    if(m_frame.isEmpty()||!link||m_offsetGap||(expected>0&&m_frame.size()<expected)||!m_currentTime.isValid()){
        ++m_skippedPacketCount;
    }else if(m_linkType!=0&&m_linkType!=link){
        ++m_skippedPacketCount;
    }else{
        if(m_linkType==0)m_linkType=link;
        if(!m_headerWritten){out+=globalHeader(m_linkType);m_headerWritten=true;}
        const QDateTime ts(m_date,m_currentTime,Qt::LocalTime);const qint64 secs=ts.toSecsSinceEpoch();
        if(secs>=0&&secs<=qint64(std::numeric_limits<quint32>::max())){
            appendLe32(out,quint32(secs));appendLe32(out,quint32(m_currentUsec));appendLe32(out,quint32(m_frame.size()));appendLe32(out,quint32(m_frame.size()));out+=m_frame;++m_packetCount;
        }else ++m_skippedPacketCount;
    }
    m_haveCurrent=false;m_frame.clear();m_offsetGap=false;m_currentTime=QTime();m_currentUsec=0;
    return out;
}

QByteArray TcpdumpTextStreamParser::finish()
{
    QByteArray out;
    if(!m_lineBuffer.isEmpty()){out+=processLine(QString::fromLocal8Bit(m_lineBuffer));m_lineBuffer.clear();}
    out+=finishCurrent(true);
    return out;
}
