#include "PacketParser.h"
#include <QHostAddress>
#include <QtGlobal>

static quint16 be16(const uchar* p){return quint16((quint16(p[0])<<8)|p[1]);}
static quint32 be32(const uchar* p){return (quint32(p[0])<<24)|(quint32(p[1])<<16)|(quint32(p[2])<<8)|p[3];}
static QString ip4(const uchar* p){return QStringLiteral("%1.%2.%3.%4").arg(p[0]).arg(p[1]).arg(p[2]).arg(p[3]);}

ParsedPacket PacketParser::parse(const PcapRecord& record, quint32 linkType){
    ParsedPacket o; o.capturedLength=record.includedLength;
    qint64 ms=qint64(record.tsSec)*1000 + (record.nanosecondResolution ? record.tsFraction/1000000 : record.tsFraction/1000);
    o.timestamp=QDateTime::fromMSecsSinceEpoch(ms,Qt::UTC);
    const auto* b=reinterpret_cast<const uchar*>(record.data.constData()); int n=record.data.size(), off=0; quint16 etherType=0x0800;
    if(linkType==PcapLinkType::Ethernet){
        if(n<14){o.error="Truncated Ethernet frame";return o;}
        etherType=be16(b+12);off=14;
        // Support stacked 802.1Q/802.1ad tags (VLAN/QinQ). Each tag contributes 4 bytes.
        while((etherType==0x8100||etherType==0x88a8||etherType==0x9100)){
            if(n<off+4){o.error="Truncated VLAN header";return o;}
            etherType=be16(b+off+2);off+=4;
        }
        if(etherType!=0x0800){o.error="Non-IPv4 Ethernet frame";return o;}
    }
    else if(linkType==PcapLinkType::LinuxSll){
        if(n<16){o.error="Truncated Linux SLL frame";return o;}
        etherType=be16(b+14);off=16;if(etherType!=0x0800){o.error="Non-IPv4 SLL frame";return o;}
    }
    else if(linkType==PcapLinkType::LinuxSll2){
        if(n<20){o.error="Truncated Linux SLL2 frame";return o;}
        etherType=be16(b);off=20;if(etherType!=0x0800){o.error="Non-IPv4 SLL2 frame";return o;}
    }
    else if(linkType==PcapLinkType::Raw){off=0;}
    else {o.error=QStringLiteral("Unsupported PCAP link type %1").arg(linkType);return o;}
    if(n<off+20){o.error="Truncated IPv4 header";return o;} const uchar* ip=b+off; if((ip[0]>>4)!=4){o.error="Not IPv4";return o;} int ihl=(ip[0]&0x0f)*4; if(ihl<20||n<off+ihl){o.error="Invalid IPv4 header length";return o;}
    o.ipTotalLength=be16(ip+2);
    if(o.ipTotalLength<quint16(ihl)){o.error="Invalid IPv4 total length";return o;}
    const int capturedIpBytes=n-off;
    const int boundedIpBytes=qMin(capturedIpBytes,int(o.ipTotalLength));
    o.sourceIp=ip4(ip+12);o.destinationIp=ip4(ip+16); quint8 proto=ip[9]; const uchar* l4=ip+ihl; int l4n=boundedIpBytes-ihl;
    if(proto==6){
        if(l4n<20){o.error="Truncated TCP header";return o;}
        o.protocol="TCP";o.sourcePort=be16(l4);o.destinationPort=be16(l4+2);o.sequence=be32(l4+4);o.acknowledgement=be32(l4+8);o.tcpFlags=l4[13];
        const int tcpHeaderLength=(l4[12]>>4)*4;
        if(tcpHeaderLength<20||l4n<tcpHeaderLength){o.error="Invalid TCP header length";return o;}
        o.tcpHeaderLength=quint8(tcpHeaderLength);
        const int payloadBytes=qMax(0,l4n-tcpHeaderLength);
        o.tcpPayloadLength=quint32(payloadBytes);
        if(payloadBytes>0)o.payload=QByteArray(reinterpret_cast<const char*>(l4+tcpHeaderLength),payloadBytes);
        QString flagText;
        if(o.tcpFlags&0x04) flagText="RST";
        else if((o.tcpFlags&0x12)==0x12) flagText="SYN-ACK";
        else if(o.tcpFlags&0x02) flagText="SYN";
        else if(o.tcpFlags&0x01) flagText="FIN";
        else if((o.tcpFlags&0x18)==0x18) flagText="PSH-ACK";
        else if(o.tcpFlags&0x10) flagText="ACK";
        else flagText=QStringLiteral("flags 0x%1").arg(o.tcpFlags,2,16,QLatin1Char('0'));
        o.summary=QStringLiteral("%1 → %2 %3").arg(o.sourcePort).arg(o.destinationPort).arg(flagText);
    }
    else if(proto==17){if(l4n<8){o.error="Truncated UDP header";return o;}o.protocol="UDP";o.sourcePort=be16(l4);o.destinationPort=be16(l4+2);o.summary=QStringLiteral("%1 → %2").arg(o.sourcePort).arg(o.destinationPort);}
    else if(proto==1){if(l4n<4){o.error="Truncated ICMP header";return o;}o.protocol="ICMP";o.icmpType=l4[0];o.summary=(o.icmpType==8)?"Echo request":(o.icmpType==0)?"Echo reply":QStringLiteral("ICMP type %1").arg(o.icmpType);}
    else {o.protocol=QStringLiteral("IP/%1").arg(proto);o.summary=o.protocol;}
    o.valid=true;return o;
}
