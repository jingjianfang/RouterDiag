#include "ConnectivityProbe.h"
#include <QRegularExpression>
#include <QtGlobal>

bool ConnectivityProbe::isValidIpv4(const QString& ip){
    if(ip.isEmpty() || ip != ip.trimmed()) return false;
    static const QRegularExpression re(
        QStringLiteral(R"(^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$)"));
    return re.match(ip).hasMatch();
}

bool ConnectivityProbe::isUsableWanIpv4(const QString& ip){
    if(!isValidIpv4(ip)) return false;
    const QString value=ip.trimmed();
    // 0.0.0.0 is an unspecified address, not an assigned WAN address.
    // Keep private/CGNAT ranges valid because cellular WANs commonly use them.
    return value!=QStringLiteral("0.0.0.0") && value!=QStringLiteral("255.255.255.255");
}

namespace {
bool ipv4ToUInt(const QString& ip,quint32* value)
{
    if(!value || !ConnectivityProbe::isValidIpv4(ip))return false;
    const QStringList parts=ip.split(QLatin1Char('.'));
    if(parts.size()!=4)return false;
    quint32 out=0;
    for(const QString& part:parts)out=(out<<8)|quint32(part.toUInt());
    *value=out;
    return true;
}

bool validContiguousNetmask(quint32 mask)
{
    bool sawZero=false;
    for(int bit=31;bit>=0;--bit){
        const bool one=(mask&(quint32(1)<<bit))!=0;
        if(!one)sawZero=true;
        else if(sawZero)return false;
    }
    return true;
}
}

bool ConnectivityProbe::sameIpv4Subnet(const QString& firstIp,const QString& secondIp,const QString& netmask)
{
    quint32 first=0,second=0,mask=0;
    if(!ipv4ToUInt(firstIp,&first)||!ipv4ToUInt(secondIp,&second)||!ipv4ToUInt(netmask,&mask))return false;
    if(!validContiguousNetmask(mask))return false;
    return (first&mask)==(second&mask);
}

bool ConnectivityProbe::isUsableWanInterfaceName(const QString& name){
    const QString value=name.trimmed();
    if(value.isEmpty() || value!=name || value.contains(QRegularExpression(QStringLiteral("\\s")))) return false;
    static const QRegularExpression ifaceRe(QStringLiteral(R"(^[A-Za-z][A-Za-z0-9_.:-]*$)"));
    if(!ifaceRe.match(value).hasMatch()) return false;
    const QString low=value.toLower();
    // br* and lan* are LAN-side bridge/interface names on Four-Faith routers.
    // They remain valid for terminal-side capture, but must never be promoted to WAN.
    if(low==QStringLiteral("lo") || low.startsWith(QStringLiteral("br")) || low.startsWith(QStringLiteral("lan"))) return false;
    return true;
}

QString ConnectivityProbe::buildPingCommand(const QString& ip,int count){
    if(!isValidIpv4(ip) || count < 1 || count > 20) return {};
    return QStringLiteral("ping -c %1 %2").arg(count).arg(ip);
}

PingResult ConnectivityProbe::parsePingOutput(const QString& output){
    PingResult r;
    r.rawOutput=output;
    const QString lower=output.toLower();

    static const QRegularExpression stats(
        QStringLiteral(R"((\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received(?:,\s*(\d+)%\s*packet loss)?)"),
        QRegularExpression::CaseInsensitiveOption);
    const auto m=stats.match(output);
    if(m.hasMatch()){
        r.validOutput=true;
        r.transmitted=m.captured(1).toInt();
        r.received=m.captured(2).toInt();
        if(!m.captured(3).isEmpty())r.packetLossPercent=m.captured(3).toInt();
        else if(r.transmitted>0)r.packetLossPercent=qBound(0,100-(r.received*100/r.transmitted),100);
        r.reachable=r.received>0;
    }

    static const QRegularExpression rttBusyBox(
        QStringLiteral(R"((?:round-trip|rtt)[^=]*=\s*([0-9.]+)\s*/\s*([0-9.]+)\s*/\s*([0-9.]+)(?:\s*/[0-9.]+)?\s*ms)"),
        QRegularExpression::CaseInsensitiveOption);
    const auto rm=rttBusyBox.match(output);
    if(rm.hasMatch()){
        r.validOutput=true;
        r.minRttMs=rm.captured(1).toDouble();
        r.avgRttMs=rm.captured(2).toDouble();
        r.maxRttMs=rm.captured(3).toDouble();
    }

    static const QRegularExpression rxBytes(QStringLiteral(R"((?:bytes from|icmp_seq=|seq=))"),QRegularExpression::CaseInsensitiveOption);
    if(rxBytes.match(output).hasMatch()){r.validOutput=true;r.reachable=true;}

    if(lower.contains(QStringLiteral("network is unreachable"))){
        r.validOutput=true;r.reachable=false;r.failureKind=PingFailureKind::NetworkUnreachable;
        r.failureReason=QStringLiteral("本机/路由器无可用路由（Network is unreachable）");
    }
    else if(lower.contains(QStringLiteral("destination host unreachable"))){
        r.validOutput=true;r.reachable=false;r.failureKind=PingFailureKind::DestinationHostUnreachable;
        r.failureReason=QStringLiteral("目标主机不可达（Destination Host Unreachable）");
    }
    else if(lower.contains(QStringLiteral("bad address"))||lower.contains(QStringLiteral("unknown host"))){
        r.validOutput=true;r.reachable=false;r.failureKind=PingFailureKind::AddressResolutionFailed;
        r.failureReason=QStringLiteral("目标地址解析失败");
    }
    else if(r.validOutput && !r.reachable && r.received==0){
        r.failureKind=PingFailureKind::NoEchoReply;
        r.failureReason=QStringLiteral("目标未返回 ICMP Echo Reply");
    }

    if(r.transmitted>=0 && r.received>=0){
        QString summary=QStringLiteral("Ping: transmitted=%1, received=%2").arg(r.transmitted).arg(r.received);
        if(r.packetLossPercent>=0)summary+=QStringLiteral(", loss=%1%").arg(r.packetLossPercent);
        r.evidence<<summary;
    }else if(r.reachable){
        r.evidence<<QStringLiteral("Ping输出包含应答报文");
    }
    if(r.avgRttMs>=0)r.evidence<<QStringLiteral("RTT min/avg/max=%1/%2/%3 ms").arg(r.minRttMs,0,'f',1).arg(r.avgRttMs,0,'f',1).arg(r.maxRttMs,0,'f',1);
    if(!r.failureReason.isEmpty())r.evidence<<r.failureReason;
    return r;
}
