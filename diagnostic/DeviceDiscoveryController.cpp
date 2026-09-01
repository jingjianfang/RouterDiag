#include "DeviceDiscoveryController.h"
#include "ConnectivityProbe.h"
#include "AtStatusParser.h"
#include "telnet/TelnetClient.h"
#include <QRegularExpression>
#include <QPair>

namespace {
int interfacePriority(const QString& name)
{
    if(!ConnectivityProbe::isUsableWanInterfaceName(name)) return -1;
    const QString n=name.toLower();
    // Fallback discovery is intentionally conservative. Generic eth/vlan interfaces are
    // accepted when named by NVRAM/default-route evidence, but are not guessed as WAN.
    if(QRegularExpression(QStringLiteral(R"(^ppp\d+$)")).match(n).hasMatch()) return 100;
    if(n.startsWith(QStringLiteral("usb")) || n.startsWith(QStringLiteral("wwan")) ||
       n.startsWith(QStringLiteral("rmnet")) || n.startsWith(QStringLiteral("cell")) ||
       n.startsWith(QStringLiteral("wan"))) return 90;
    return -1;
}

QString firstValidIpv4(const QString& text)
{
    static const QRegularExpression ipRe(QStringLiteral(R"((\d{1,3}(?:\.\d{1,3}){3}))"));
    auto it=ipRe.globalMatch(text);
    while(it.hasNext()){
        const QString ip=it.next().captured(1);
        if(ConnectivityProbe::isUsableWanIpv4(ip)) return ip;
    }
    return {};
}

QString firstInterfaceName(const QString& text)
{
    static const QRegularExpression ifaceRe(QStringLiteral(R"(^[A-Za-z][A-Za-z0-9_.:-]*$)"));
    const QStringList lines=text.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(QString line:lines){
        line=line.trimmed();
        if(line.startsWith(QStringLiteral("nvram ")) || line.endsWith(QLatin1Char('#')) ||
           line.endsWith(QLatin1Char('$')) || line.endsWith(QLatin1Char('>'))) continue;
        if(ifaceRe.match(line).hasMatch() && ConnectivityProbe::isUsableWanInterfaceName(line)) return line;
    }
    return {};
}


QString boundedAtPayload(const QString& output)
{
    const QStringList lines=output.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    QStringList payload;
    bool inside=false;
    bool sawMarker=false;
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(line.startsWith(QStringLiteral("__FF_AT_BEGIN__="))){inside=true;sawMarker=true;continue;}
        if(line.startsWith(QStringLiteral("__FF_AT_END__="))){inside=false;break;}
        if(inside)payload<<raw;
    }
    return sawMarker?payload.join(QLatin1Char('\n')):output;
}

bool isPlausibleModuleIdentity(const QString& value)
{
    const QString v=value.trimmed();
    if(v.size()<2 || v.size()>96)return false;
    const QString low=v.toLower();
    const QStringList shellNoise={QStringLiteral("cat "),QStringLiteral("printf "),QStringLiteral("/tmp/"),
        QStringLiteral("/dev/"),QStringLiteral("sleep "),QStringLiteral("kill "),QStringLiteral("wait "),
        QStringLiteral("grep "),QStringLiteral("at_test"),QStringLiteral("__ff_at_"),QStringLiteral("cmd="),QStringLiteral("dev=")};
    for(const QString& token:shellNoise)if(low.contains(token))return false;
    if(v.contains(QLatin1Char(';')) || v.contains(QStringLiteral("$$")) || v.contains(QStringLiteral("$pid")))return false;
    if(v.compare(QStringLiteral("OK"),Qt::CaseInsensitive)==0 || v.compare(QStringLiteral("ERROR"),Qt::CaseInsensitive)==0)return false;
    return QRegularExpression(QStringLiteral("[A-Za-z0-9]"),QRegularExpression::UseUnicodePropertiesOption).match(v).hasMatch();
}

bool isAtNoise(const QString& line,const QString& command)
{
    const QString t=line.trimmed();
    const QString low=t.toLower();
    if(t.isEmpty() || t.compare(QStringLiteral("OK"),Qt::CaseInsensitive)==0 ||
       t.compare(QStringLiteral("ERROR"),Qt::CaseInsensitive)==0 ||
       t.contains(QStringLiteral("COMMAND TIMEOUT"),Qt::CaseInsensitive) ||
       t.startsWith(QStringLiteral("__FF_AT_")) || t.startsWith(QStringLiteral("-->")) ||
       t.startsWith(QStringLiteral("<--")) || low.startsWith(QStringLiteral("a simple at command test tool")) ||
       low==QStringLiteral("usage:") || low.startsWith(QStringLiteral("pls select a tty dev")) ||
       low.startsWith(QStringLiteral("from this version")) || t.contains(QStringLiteral("dev='")) ||
       t.contains(QStringLiteral("cmd='")) || t.contains(QStringLiteral("printf '%s")) ||
       t.contains(QStringLiteral("at_test \"$dev\"")) || t.contains(QStringLiteral("cat \"$dev\""))) return true;
    if(t.compare(command,Qt::CaseInsensitive)==0) return true;
    if(t.endsWith(QLatin1Char('#')) || t.endsWith(QLatin1Char('$')) || t.endsWith(QLatin1Char('>'))) return true;
    return false;
}

QStringList atiIdentityCandidates(const QString& output)
{
    QStringList candidates;
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(isAtNoise(line,QStringLiteral("ATI")))continue;
        if(line.startsWith(QStringLiteral("Manufacturer:"),Qt::CaseInsensitive) ||
           line.startsWith(QStringLiteral("Model:"),Qt::CaseInsensitive) ||
           line.startsWith(QStringLiteral("Revision:"),Qt::CaseInsensitive) ||
           line.startsWith(QStringLiteral("Firmware:"),Qt::CaseInsensitive) ||
           line.startsWith(QStringLiteral("IMEI:"),Qt::CaseInsensitive))continue;
        if(!line.startsWith(QStringLiteral("AT"),Qt::CaseInsensitive) &&
           !line.startsWith(QLatin1Char('+')) && isPlausibleModuleIdentity(line))candidates<<line;
    }
    return candidates;
}
}

namespace {
QString netmaskFromPrefix(int prefix)
{
    if(prefix<0 || prefix>32)return {};
    quint32 mask=prefix==0?0u:(0xffffffffu<<(32-prefix));
    return QStringLiteral("%1.%2.%3.%4")
        .arg((mask>>24)&0xffu).arg((mask>>16)&0xffu).arg((mask>>8)&0xffu).arg(mask&0xffu);
}
}

QList<DeviceInterfaceInfo> DeviceDiscoveryParser::parseInterfaces(const QString& output)
{
    QList<DeviceInterfaceInfo> result;
    DeviceInterfaceInfo current;
    bool haveCurrent=false;

    auto flush=[&](){
        if(haveCurrent && !current.name.isEmpty()) result.push_back(current);
        current=DeviceInterfaceInfo{};
        haveCurrent=false;
    };

    const QStringList lines=output.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    static const QRegularExpression ifconfigLegacyHeader(QStringLiteral(R"(^([A-Za-z0-9_.:-]+)\s+Link\s+encap:)"));
    static const QRegularExpression ifconfigModernHeader(QStringLiteral(R"(^([A-Za-z0-9_.:-]+):\s+flags=)"));
    static const QRegularExpression ipHeader(QStringLiteral(R"(^\d+:\s+([^:@\s]+)(?:@[^:]+)?:\s*<([^>]*)>)"));
    static const QRegularExpression inetRe(QStringLiteral(R"(\binet(?:\s+addr:|\s+)(\d{1,3}(?:\.\d{1,3}){3}))"));
    static const QRegularExpression legacyMaskRe(QStringLiteral(R"(\bMask:(\d{1,3}(?:\.\d{1,3}){3}))"));
    static const QRegularExpression modernMaskRe(QStringLiteral(R"(\bnetmask\s+(\d{1,3}(?:\.\d{1,3}){3}))"),QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression cidrRe(QStringLiteral(R"(\binet\s+\d{1,3}(?:\.\d{1,3}){3}/(\d{1,2}))"));

    for(QString line:lines){
        const QString trimmed=line.trimmed();
        auto m=ipHeader.match(trimmed);
        if(m.hasMatch()){
            flush();
            current.name=m.captured(1);
            current.up=m.captured(2).contains(QStringLiteral("UP"),Qt::CaseInsensitive);
            haveCurrent=true;
            continue;
        }
        m=ifconfigLegacyHeader.match(trimmed);
        if(!m.hasMatch())m=ifconfigModernHeader.match(trimmed);
        if(m.hasMatch()){
            flush();
            current.name=m.captured(1);
            current.up=trimmed.contains(QStringLiteral("UP"),Qt::CaseInsensitive);
            haveCurrent=true;
            continue;
        }
        if(!haveCurrent) continue;
        if(trimmed.contains(QStringLiteral("UP"),Qt::CaseInsensitive)) current.up=true;
        m=inetRe.match(trimmed);
        if(m.hasMatch() && current.ipv4.isEmpty()){
            const QString ip=m.captured(1);
            if(ConnectivityProbe::isValidIpv4(ip)) current.ipv4=ip;
        }
        auto maskMatch=legacyMaskRe.match(trimmed);
        if(!maskMatch.hasMatch())maskMatch=modernMaskRe.match(trimmed);
        if(maskMatch.hasMatch() && current.netmask.isEmpty()){
            const QString mask=maskMatch.captured(1);
            if(ConnectivityProbe::isValidIpv4(mask))current.netmask=mask;
        }
        if(current.netmask.isEmpty()){
            const auto cidr=cidrRe.match(trimmed);
            if(cidr.hasMatch())current.netmask=netmaskFromPrefix(cidr.captured(1).toInt());
        }
    }
    flush();
    QList<DeviceInterfaceInfo> unique;
    for(const auto& info:result){
        int existing=-1;for(int i=0;i<unique.size();++i)if(unique.at(i).name==info.name){existing=i;break;}
        if(existing<0)unique.push_back(info);
        else{
            if(unique[existing].ipv4.isEmpty()&&!info.ipv4.isEmpty())unique[existing].ipv4=info.ipv4;
            if(unique[existing].netmask.isEmpty()&&!info.netmask.isEmpty())unique[existing].netmask=info.netmask;
            unique[existing].up=unique[existing].up||info.up;
        }
    }
    return unique;
}

DeviceDiscoveryResult DeviceDiscoveryParser::buildResult(const QString& wanIfnameOutput,
                                                          const QString& wanIpOutput,
                                                          const QString& backupWanIpOutput,
                                                          const QString& ifconfigOutput,
                                                          const QString& routeOutput,
                                                          const QString& backupWanIfnameOutput,
                                                          const QString& wanIfname2Output,
                                                          const QString& commWanIpOutput,
                                                          bool backupActive)
{
    DeviceDiscoveryResult r;
    r.interfaces=parseInterfaces(ifconfigOutput);

    const QString primaryIf=firstInterfaceName(wanIfnameOutput);
    const QString backupIf=firstInterfaceName(backupWanIfnameOutput);
    const QString secondaryIf=firstInterfaceName(wanIfname2Output);
    r.wanNvramIp=firstValidIpv4(wanIpOutput);
    r.backupWanIp=firstValidIpv4(backupWanIpOutput);
    r.commWanIp=firstValidIpv4(commWanIpOutput);

    // Route data remains useful evidence, but it is intentionally below live ifconfig +
    // explicit NVRAM WAN hints. Four-Faith dual-WAN firmware can keep routes that do not
    // represent the configured cellular WAN selected by its NVRAM state.
    r.defaultRouteChecked=routeOutput.contains(QStringLiteral("__FF_ROUTE_CHECK__")) || !routeOutput.trimmed().isEmpty();
    const QStringList routeLines=routeOutput.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    static const QRegularExpression ipDefault(QStringLiteral(R"(^\s*default(?:\s+via\s+(\d{1,3}(?:\.\d{1,3}){3}))?.*?\s+dev\s+([A-Za-z0-9_.:-]+))"),QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression routeN(QStringLiteral(R"(^\s*0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+0\.0\.0\.0\s+.*\s([A-Za-z0-9_.:-]+)\s*$)"),QRegularExpression::CaseInsensitiveOption);
    for(const QString& raw:routeLines){
        const QString line=raw.trimmed();
        auto m=ipDefault.match(line);
        if(m.hasMatch()){r.defaultRoutePresent=true;r.defaultGateway=m.captured(1);r.defaultRouteInterface=m.captured(2);break;}
        m=routeN.match(line);
        if(m.hasMatch()){r.defaultRoutePresent=true;r.defaultGateway=m.captured(1);r.defaultRouteInterface=m.captured(2);break;}
    }

    auto interfaceIndex=[&](const QString& name)->int{
        for(int i=0;i<r.interfaces.size();++i)if(r.interfaces.at(i).name==name)return i;
        return -1;
    };
    auto interfaceIp=[&](const QString& name)->QString{
        const int i=interfaceIndex(name);
        return i>=0?r.interfaces.at(i).ipv4:QString();
    };
    auto interfaceUp=[&](const QString& name)->bool{
        const int i=interfaceIndex(name);
        return i>=0 && r.interfaces.at(i).up;
    };

    struct Hint { QString name; QString source; };
    QList<Hint> hints;
    auto addHint=[&](const QString& name,const QString& source){
        if(name.isEmpty() || interfaceIndex(name)<0)return;
        for(const auto& h:hints)if(h.name==name)return;
        hints.push_back({name,source});
    };
    if(backupActive){
        addHint(backupIf,QStringLiteral("NVRAM接口 bkup_wan_ifname（当前备卡）"));
        addHint(primaryIf,QStringLiteral("NVRAM接口 wan_ifname"));
    }else{
        addHint(primaryIf,QStringLiteral("NVRAM接口 wan_ifname"));
        addHint(backupIf,QStringLiteral("NVRAM接口 bkup_wan_ifname"));
    }
    addHint(secondaryIf,QStringLiteral("NVRAM接口 wan_ifname2"));

    QString selectedHint;
    auto chooseHint=[&](bool requireLive,bool requireUp)->bool{
        for(const auto& h:hints){
            const QString live=interfaceIp(h.name);
            if(requireLive && !ConnectivityProbe::isUsableWanIpv4(live))continue;
            if(requireUp && !interfaceUp(h.name))continue;
            r.wanIfname=h.name;selectedHint=h.source;return true;
        }
        return false;
    };

    // A displayed WAN is the currently active WAN, not merely a configured WAN.
    // NVRAM names are strong hints only when ifconfig confirms the interface is UP and
    // currently owns a usable IPv4 address. Down/stale configured WANs stay out of the
    // active result so an old wan_ipaddr cannot masquerade as a live link.
    chooseHint(true,true);

    // If the interface-name NVRAM is empty/stale, matching a NVRAM WAN IP to an ifconfig
    // address is still strong combined evidence and is preferred over the routing table.
    if(r.wanIfname.isEmpty()){
        const QList<QPair<QString,QString>> ipHints=backupActive
            ?QList<QPair<QString,QString>>{{r.backupWanIp,QStringLiteral("bkup_wan_ipaddr（当前备卡）")},{r.commWanIp,QStringLiteral("comm_wan_ipaddr")},{r.wanNvramIp,QStringLiteral("wan_ipaddr")}}
            :QList<QPair<QString,QString>>{{r.wanNvramIp,QStringLiteral("wan_ipaddr")},{r.commWanIp,QStringLiteral("comm_wan_ipaddr")},{r.backupWanIp,QStringLiteral("bkup_wan_ipaddr")}};
        for(const auto& ipHint:ipHints){
            if(ipHint.first.isEmpty())continue;
            for(const auto& info:r.interfaces){
                if(info.up && ConnectivityProbe::isUsableWanIpv4(info.ipv4) &&
                   info.ipv4==ipHint.first && ConnectivityProbe::isUsableWanInterfaceName(info.name)){
                    r.wanIfname=info.name;selectedHint=ipHint.second;break;
                }
            }
            if(!r.wanIfname.isEmpty())break;
        }
    }

    // Default route is only a fallback after ifconfig + NVRAM cannot identify the WAN.
    if(r.wanIfname.isEmpty() && r.defaultRoutePresent &&
       ConnectivityProbe::isUsableWanInterfaceName(r.defaultRouteInterface) &&
       interfaceIndex(r.defaultRouteInterface)>=0 && interfaceUp(r.defaultRouteInterface) &&
       ConnectivityProbe::isUsableWanIpv4(interfaceIp(r.defaultRouteInterface))){
        r.wanIfname=r.defaultRouteInterface;
        selectedHint=QStringLiteral("默认路由");
    }

    if(r.wanIfname.isEmpty()){
        int best=-1;
        for(const auto& info:r.interfaces){
            if(!info.up || !ConnectivityProbe::isUsableWanIpv4(info.ipv4)) continue;
            const int base=interfacePriority(info.name);
            if(base<0) continue;
            const int score=base+(info.up?5:0);
            if(score>best){best=score;r.wanIfname=info.name;selectedHint=QStringLiteral("接口特征");}
        }
    }

    if(ConnectivityProbe::isUsableWanInterfaceName(r.wanIfname)){
        const QString live=interfaceIp(r.wanIfname);
        if(ConnectivityProbe::isUsableWanIpv4(live)){
            r.wanIp=live;
            r.wanIpSource=selectedHint==QStringLiteral("默认路由")
                ?QStringLiteral("接口 %1 IPv4（默认路由辅助确认）").arg(r.wanIfname)
                :QStringLiteral("接口 %1 IPv4（%2）").arg(r.wanIfname,selectedHint.isEmpty()?QStringLiteral("ifconfig"):selectedHint);
        }else{
            QString fallback;
            QString fallbackSource;
            if(r.wanIfname==primaryIf && !r.wanNvramIp.isEmpty()){fallback=r.wanNvramIp;fallbackSource=QStringLiteral("wan_ipaddr");}
            else if(r.wanIfname==backupIf){
                if(!r.backupWanIp.isEmpty()){fallback=r.backupWanIp;fallbackSource=QStringLiteral("bkup_wan_ipaddr");}
                else if(!r.commWanIp.isEmpty()){fallback=r.commWanIp;fallbackSource=QStringLiteral("comm_wan_ipaddr");}
            }else if(r.wanIfname==secondaryIf){
                if(!r.wanNvramIp.isEmpty()){fallback=r.wanNvramIp;fallbackSource=QStringLiteral("wan_ipaddr");}
                else if(!r.commWanIp.isEmpty()){fallback=r.commWanIp;fallbackSource=QStringLiteral("comm_wan_ipaddr");}
                else if(!r.backupWanIp.isEmpty()){fallback=r.backupWanIp;fallbackSource=QStringLiteral("bkup_wan_ipaddr");}
            }
            if(!fallback.isEmpty()){
                r.wanIp=fallback;
                r.wanIpSource=QStringLiteral("%1（%2 已由 ifconfig 确认）").arg(fallbackSource,r.wanIfname);
            }
        }
    }

    if(!ConnectivityProbe::isUsableWanInterfaceName(r.wanIfname)){
        r.wanIfname.clear();r.wanIp.clear();r.wanIpSource.clear();
    }

    for(const auto& info:r.interfaces){
        if(info.name==r.wanIfname){r.wanInterfaceStateKnown=true;r.wanInterfaceUp=info.up;break;}
    }
    return r;
}

QStringList DeviceDiscoveryParser::parseModuleDevices(const QString& output)
{
    QStringList result;
    static const QRegularExpression deviceRe(QStringLiteral(R"((/dev/(?:ttyUSB|ttyACM)\d+))"),QRegularExpression::CaseInsensitiveOption);
    auto it=deviceRe.globalMatch(output);
    while(it.hasNext()){
        const QString device=it.next().captured(1);
        if(!result.contains(device)) result<<device;
    }
    return result;
}

bool DeviceDiscoveryParser::atResponseOk(const QString& output)
{
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines)
        if(raw.trimmed().compare(QStringLiteral("OK"),Qt::CaseInsensitive)==0) return true;
    return false;
}

QString DeviceDiscoveryParser::parseAtValue(const QString& output,const QString& command)
{
    QString prefix;
    QString namedPrefix;
    if(command.compare(QStringLiteral("AT+CGMI"),Qt::CaseInsensitive)==0){prefix=QStringLiteral("+CGMI:");namedPrefix=QStringLiteral("Manufacturer:");}
    else if(command.compare(QStringLiteral("AT+CGMM"),Qt::CaseInsensitive)==0){prefix=QStringLiteral("+CGMM:");namedPrefix=QStringLiteral("Model:");}
    else if(command.compare(QStringLiteral("AT+CGMR"),Qt::CaseInsensitive)==0){prefix=QStringLiteral("+CGMR:");namedPrefix=QStringLiteral("Revision:");}

    QStringList candidates;
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(isAtNoise(line,command)) continue;
        if(!prefix.isEmpty() && line.startsWith(prefix,Qt::CaseInsensitive)){
            const QString value=line.mid(prefix.size()).trimmed();
            return isPlausibleModuleIdentity(value)?value:QString();
        }
        if(!namedPrefix.isEmpty() && line.startsWith(namedPrefix,Qt::CaseInsensitive)){
            const QString value=line.mid(namedPrefix.size()).trimmed();
            return isPlausibleModuleIdentity(value)?value:QString();
        }
        if(!line.startsWith(QStringLiteral("AT"),Qt::CaseInsensitive) && !line.startsWith(QLatin1Char('+')) && isPlausibleModuleIdentity(line))candidates<<line;
    }
    return candidates.isEmpty()?QString():candidates.first().trimmed();
}


QString DeviceDiscoveryParser::parseAtTaggedValue(const QString& output,const QString& prefix)
{
    const QString marker=prefix.endsWith(QLatin1Char(':'))?prefix:(prefix+QLatin1Char(':'));
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(line.startsWith(marker,Qt::CaseInsensitive)) return line.mid(marker.size()).trimmed();
    }
    return {};
}

QString DeviceDiscoveryParser::parseAtiManufacturer(const QString& output)
{
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(line.startsWith(QStringLiteral("Manufacturer:"),Qt::CaseInsensitive)){
            const QString value=line.mid(QStringLiteral("Manufacturer:").size()).trimmed();
            return isPlausibleModuleIdentity(value)?value:QString();
        }
    }
    const QStringList candidates=atiIdentityCandidates(output);
    return candidates.isEmpty()?QString():candidates.at(0).trimmed();
}

QString DeviceDiscoveryParser::parseAtiModel(const QString& output)
{
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(line.startsWith(QStringLiteral("Model:"),Qt::CaseInsensitive)){
            const QString value=line.mid(QStringLiteral("Model:").size()).trimmed();
            return isPlausibleModuleIdentity(value)?value:QString();
        }
    }
    const QStringList candidates=atiIdentityCandidates(output);
    if(candidates.size()>=2)return candidates.at(1).trimmed();
    return candidates.isEmpty()?QString():candidates.first().trimmed();
}

QString DeviceDiscoveryParser::parseAtiFirmware(const QString& output)
{
    const QString bounded=boundedAtPayload(output);
    const QStringList lines=bounded.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        if(line.startsWith(QStringLiteral("Revision:"),Qt::CaseInsensitive)){
            const QString value=line.mid(QStringLiteral("Revision:").size()).trimmed();
            return isPlausibleModuleIdentity(value)?value:QString();
        }
        if(line.startsWith(QStringLiteral("Firmware:"),Qt::CaseInsensitive)){
            const QString value=line.mid(QStringLiteral("Firmware:").size()).trimmed();
            return isPlausibleModuleIdentity(value)?value:QString();
        }
    }
    const QStringList candidates=atiIdentityCandidates(output);
    return candidates.size()>=3?candidates.at(2).trimmed():QString();
}

DeviceDiscoveryController::DeviceDiscoveryController(TelnetClient* client,QObject* parent)
    :QObject(parent),m_client(client)
{
    if(m_client){
        connect(m_client,&TelnetClient::commandFinished,this,[this](const QString& command,const QString& output){
            if(!m_running || command!=m_pendingCommand) return;
            handleCommandResult(command,output);
            m_pendingCommand.clear();
            runNext();
        });
    }
}

QString DeviceDiscoveryController::cleanScalar(const QString& output)
{
    const QStringList lines=output.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(QString line:lines){
        line=line.trimmed();
        if(line.isEmpty() || line.startsWith(QStringLiteral("nvram ")) || line.endsWith(QLatin1Char('#')) ||
           line.endsWith(QLatin1Char('$')) || line.endsWith(QLatin1Char('>'))) continue;
        if(!line.contains(QStringLiteral("COMMAND TIMEOUT"))) return line;
    }
    return {};
}

QString DeviceDiscoveryController::buildFastNvramCommand()
{
    // One shell round-trip, but every value is still read with `nvram get` as requested.
    // The explicit key=value prefixes make wrapped BusyBox console output deterministic.
    return QStringLiteral(
        "printf 'this_is_bkup='; nvram get this_is_bkup; "
        "printf 'wan_ifname='; nvram get wan_ifname; printf 'wan_iface='; nvram get wan_iface; "
        "printf 'bkup_wan_ifname='; nvram get bkup_wan_ifname; printf 'wan_ifname2='; nvram get wan_ifname2; "
        "printf 'wan_ipaddr='; nvram get wan_ipaddr; printf 'bkup_wan_ipaddr='; nvram get bkup_wan_ipaddr; "
        "printf 'comm_wan_ipaddr='; nvram get comm_wan_ipaddr; printf 'wan_gateway='; nvram get wan_gateway; "
        "printf 'wan_netmask='; nvram get wan_netmask; printf 'wan_get_dns='; nvram get wan_get_dns; "
        "printf 'wanup='; nvram get wanup; printf 'bkupwanup='; nvram get bkupwanup; "
        "printf 'current_module_name='; nvram get current_module_name; printf 'submodulename='; nvram get submodulename; "
        "printf 'comm_name='; nvram get comm_name; printf 'bkup_current_module_real_name='; nvram get bkup_current_module_real_name; "
        "printf 'bkupmodulename='; nvram get bkupmodulename; printf 'comm_module_status='; nvram get comm_module_status; "
        "printf 'sim_card='; nvram get sim_card; printf 'comm_sim_card='; nvram get comm_sim_card; "
        "printf 'xsk_CPIN='; nvram get xsk_CPIN; printf 'bkup_sim_card='; nvram get bkup_sim_card; "
        "printf 'bkup_xsk_CPIN='; nvram get bkup_xsk_CPIN; printf 'comm_network='; nvram get comm_network; "
        "printf 'bkup_network='; nvram get bkup_network; printf 'comm_dial_status='; nvram get comm_dial_status; "
        "printf 'comm_rsrp='; nvram get comm_rsrp; printf 'comm_sinr='; nvram get comm_sinr; "
        "printf 'bkup_rsrp='; nvram get bkup_rsrp; printf 'bkup_sinr='; nvram get bkup_sinr; "
        "printf 'comm_softver='; nvram get comm_softver; printf 'controldevice='; nvram get controldevice; "
        "printf '3gdata='; nvram get 3gdata; printf 'bkupcontroldevice='; nvram get bkupcontroldevice; "
        "printf 'bkup3gdata='; nvram get bkup3gdata");
}

QString DeviceDiscoveryController::fastNvramValue(const QString& output,const QString& key)
{
    const QRegularExpression re(QStringLiteral("(?:^|[\\r\\n])%1=([^\\r\\n]*)").arg(QRegularExpression::escape(key)));
    const auto match=re.match(output);
    return match.hasMatch()?match.captured(1).trimmed():QString();
}

QString DeviceDiscoveryController::buildAtCommand(const QString& device,const QString& atCommand)
{
    return QStringLiteral(
        "dev='%1'; cmd='%2'; tmp=/tmp/ff_at_probe_$$; in=/tmp/ff_at_in_$$; rm -f \"$tmp\" \"$in\"; ok=0; "
        "if command -v at_test >/dev/null 2>&1; then "
        "echo __FF_AT_METHOD__=at_test; printf '%s\\r\\n' \"$cmd\" > \"$in\"; "
        "at_test \"$dev\" < \"$in\" > \"$tmp\" 2>&1 & pid=$!; "
        "sleep 2; kill \"$pid\" 2>/dev/null; wait \"$pid\" 2>/dev/null; "
        "grep -q '^[[:space:]]*OK[[:space:]]*$' \"$tmp\" 2>/dev/null && ok=1; "
        "fi; "
        "if [ \"$ok\" != 1 ]; then "
        "echo __FF_AT_METHOD__=direct; : > \"$tmp\"; "
        "cat \"$dev\" > \"$tmp\" 2>/dev/null & pid=$!; "
        "sleep 1; printf '%s\\r\\n' \"$cmd\" > \"$dev\" 2>/dev/null; sleep 1; "
        "kill \"$pid\" 2>/dev/null; wait \"$pid\" 2>/dev/null; "
        "fi; echo \"__FF_AT_BEGIN__=$cmd\"; cat \"$tmp\" 2>/dev/null; echo \"__FF_AT_END__=$cmd\"; rm -f \"$tmp\" \"$in\"")
        .arg(device,atCommand);
}

void DeviceDiscoveryController::start()
{
    if(!m_client || !m_client->isConnected()){emit failed(QStringLiteral("Telnet控制连接未建立"));return;}
    if(m_running){emit failed(QStringLiteral("设备自动检测正在执行"));return;}
    if(m_client->isBusy()){emit failed(QStringLiteral("控制Telnet正在执行其他命令，请稍后再自动检测"));return;}
    m_commands={
        buildFastNvramCommand(),
        QStringLiteral("ifconfig 2>/dev/null"),
        QStringLiteral("echo __FF_ROUTE_CHECK__; ip route show default 2>/dev/null || route -n"),
        QStringLiteral("grep -i 'CONTROL DEVICES' /tmp/.systemlog 2>/dev/null | tail -n 5"),
        QStringLiteral("for d in /dev/ttyUSB* /dev/ttyACM*; do [ -c \"$d\" ] && echo \"$d\"; done")
    };    m_index=0;
    m_pendingCommand.clear();
    m_fastNvramOutput.clear();
    m_wanIfnameOutput.clear();
    m_backupWanIfnameOutput.clear();
    m_wanIfname2Output.clear();
    m_wanIpOutput.clear();
    m_backupWanIpOutput.clear();
    m_commWanIpOutput.clear();
    m_ifconfigOutput.clear();
    m_routeOutput.clear();
    m_moduleHintOutput.clear();
    m_moduleDeviceOutput.clear();
    m_moduleNvramDeviceOutput.clear();
    m_nvramCurrentModuleName.clear();
    m_nvramSubmoduleName.clear();
    m_nvramCommName.clear();
    m_nvramBackupModuleName.clear();m_nvramNetwork.clear();m_nvramSimStatus.clear();m_nvramFirmware.clear();
    m_nvramCommModuleStatus=-1;m_nvramCommDialStatus=-1;m_nvramWanUp=-1;m_nvramBackupWanUp=-1;
    m_nvramRsrp=999;m_nvramSinr=999;m_usingBackupCard=false;
    m_moduleCandidates.clear();
    m_moduleCandidateIndex=0;
    m_activeModuleDevice.clear();
    m_activeAtCommand.clear();
    m_moduleInfoIndex=0;
    m_moduleManufacturer.clear();
    m_moduleModel.clear();
    m_moduleFirmware.clear();
    m_simStatus.clear();
    m_cpinRaw.clear();
    m_cereg.clear();
    m_cgreg.clear();
    m_creg.clear();
    m_c5greg.clear();
    m_cgatt=-1;m_csq=-1;m_operatorName.clear();m_operatorAccessTechnology=-1;m_atErrors.clear();
    m_moduleAtResponsive=false;
    m_moduleProbeAttempted=false;
    m_phase=Phase::BaseDiscovery;
    m_running=true;
    emit progress(QStringLiteral("正在读取WAN接口和IPv4"));
    runNext();
}

void DeviceDiscoveryController::handleCommandResult(const QString& command,const QString& output)
{
    if(m_phase==Phase::BaseDiscovery){
        if(command==buildFastNvramCommand()){
            m_fastNvramOutput=output;
            m_usingBackupCard=(fastNvramValue(output,QStringLiteral("this_is_bkup"))==QStringLiteral("1"));
            const QString primaryIf=fastNvramValue(output,QStringLiteral("wan_ifname"));
            const QString wanIface=fastNvramValue(output,QStringLiteral("wan_iface"));
            m_wanIfnameOutput=!primaryIf.isEmpty()?primaryIf:wanIface;
            m_backupWanIfnameOutput=fastNvramValue(output,QStringLiteral("bkup_wan_ifname"));
            m_wanIfname2Output=fastNvramValue(output,QStringLiteral("wan_ifname2"));
            m_wanIpOutput=fastNvramValue(output,QStringLiteral("wan_ipaddr"));
            m_backupWanIpOutput=fastNvramValue(output,QStringLiteral("bkup_wan_ipaddr"));
            m_commWanIpOutput=fastNvramValue(output,QStringLiteral("comm_wan_ipaddr"));
            m_nvramCurrentModuleName=fastNvramValue(output,QStringLiteral("current_module_name"));
            m_nvramSubmoduleName=fastNvramValue(output,QStringLiteral("submodulename"));
            m_nvramCommName=fastNvramValue(output,QStringLiteral("comm_name"));
            m_nvramFirmware=fastNvramValue(output,QStringLiteral("comm_softver"));
            auto parseNvramInt=[&](const QString& key){bool valueOk=false;const int value=fastNvramValue(output,key).toInt(&valueOk);return valueOk?value:-1;};
            m_nvramCommModuleStatus=parseNvramInt(QStringLiteral("comm_module_status"));
            m_nvramCommDialStatus=parseNvramInt(QStringLiteral("comm_dial_status"));
            m_nvramWanUp=parseNvramInt(QStringLiteral("wanup"));
            m_nvramBackupWanUp=parseNvramInt(QStringLiteral("bkupwanup"));
            m_nvramBackupModuleName=fastNvramValue(output,QStringLiteral("bkup_current_module_real_name"));
            if(m_nvramBackupModuleName.isEmpty())m_nvramBackupModuleName=fastNvramValue(output,QStringLiteral("bkupmodulename"));
            m_nvramNetwork=fastNvramValue(output,m_usingBackupCard?QStringLiteral("bkup_network"):QStringLiteral("comm_network"));
            if(m_usingBackupCard && (m_nvramNetwork.isEmpty() || m_nvramNetwork.contains(QStringLiteral("NONE"),Qt::CaseInsensitive)))
                m_nvramNetwork=fastNvramValue(output,QStringLiteral("comm_network"));
            QString sim=fastNvramValue(output,m_usingBackupCard?QStringLiteral("bkup_xsk_CPIN"):QStringLiteral("xsk_CPIN"));
            if(sim.contains(QStringLiteral("READY"),Qt::CaseInsensitive))m_nvramSimStatus=QStringLiteral("READY");
            else{
                sim=fastNvramValue(output,m_usingBackupCard?QStringLiteral("bkup_sim_card"):QStringLiteral("sim_card"));
                if(sim.isEmpty())sim=fastNvramValue(output,QStringLiteral("comm_sim_card"));
                if(sim.compare(QStringLiteral("simok"),Qt::CaseInsensitive)==0 || sim==QStringLiteral("1"))m_nvramSimStatus=QStringLiteral("READY");
                else if(!sim.isEmpty())m_nvramSimStatus=sim;
            }
            bool ok=false;
            QString rsrp=fastNvramValue(output,m_usingBackupCard?QStringLiteral("bkup_rsrp"):QStringLiteral("comm_rsrp"));
            if(m_usingBackupCard && rsrp.isEmpty())rsrp=fastNvramValue(output,QStringLiteral("comm_rsrp"));
            const int rsrpValue=rsrp.toInt(&ok);if(ok)m_nvramRsrp=rsrpValue;
            ok=false;
            QString sinr=fastNvramValue(output,m_usingBackupCard?QStringLiteral("bkup_sinr"):QStringLiteral("comm_sinr"));
            if(m_usingBackupCard && sinr.isEmpty())sinr=fastNvramValue(output,QStringLiteral("comm_sinr"));
            const int sinrValue=sinr.toInt(&ok);if(ok)m_nvramSinr=sinrValue;
            const QStringList devKeys=m_usingBackupCard?QStringList{QStringLiteral("bkupcontroldevice"),QStringLiteral("bkup3gdata")}:QStringList{QStringLiteral("controldevice"),QStringLiteral("3gdata")};
            for(const QString& key:devKeys){const QString value=fastNvramValue(output,key);if(!value.isEmpty())m_moduleNvramDeviceOutput+=QLatin1Char('\n')+value;}
        }else if(command.contains(QStringLiteral("ifconfig"))) m_ifconfigOutput=output;
        else if(command.contains(QStringLiteral("route show default")) || command.contains(QStringLiteral("route -n"))) m_routeOutput=output;
        else if(command.contains(QStringLiteral("CONTROL DEVICES"))) m_moduleHintOutput=output;
        else if(command.contains(QStringLiteral("/dev/ttyUSB*"))) m_moduleDeviceOutput=output;
        return;
    }

    if(m_phase==Phase::ProbeAti){
        if(DeviceDiscoveryParser::atResponseOk(output)){
            m_moduleAtResponsive=true;
            m_activeModuleDevice=m_moduleCandidates.value(m_moduleCandidateIndex);
            m_moduleManufacturer=DeviceDiscoveryParser::parseAtiManufacturer(output);
            m_moduleModel=DeviceDiscoveryParser::parseAtiModel(output);
            m_moduleFirmware=DeviceDiscoveryParser::parseAtiFirmware(output);
            m_phase=Phase::QueryModuleInfo;
            m_moduleInfoIndex=0;
            emit progress(QStringLiteral("模组AT口已确认：%1，正在读取厂商/型号/固件、SIM和网络注册状态").arg(m_activeModuleDevice));
        }else{
            ++m_moduleCandidateIndex;
        }
        return;
    }

    if(m_phase==Phase::QueryModuleInfo){
        const QString value=DeviceDiscoveryParser::parseAtValue(output,m_activeAtCommand);
        if(m_activeAtCommand==QStringLiteral("AT+CGMI") && !value.isEmpty()) m_moduleManufacturer=value;
        else if(m_activeAtCommand==QStringLiteral("AT+CGMM") && !value.isEmpty()) m_moduleModel=value;
        else if(m_activeAtCommand==QStringLiteral("AT+CGMR") && !value.isEmpty()) m_moduleFirmware=value;
        else if(m_activeAtCommand==QStringLiteral("AT+CPIN?")){
            const QString status=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+CPIN"));
            if(!status.isEmpty()){m_simStatus=status;m_cpinRaw=QStringLiteral("+CPIN: %1").arg(status);}
            else if(output.contains(QStringLiteral("ERROR"),Qt::CaseInsensitive)){m_simStatus=QStringLiteral("ERROR");m_cpinRaw=QStringLiteral("ERROR");}
        }else if(m_activeAtCommand==QStringLiteral("AT+CEREG?")) m_cereg=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+CEREG"));
        else if(m_activeAtCommand==QStringLiteral("AT+CGREG?")) m_cgreg=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+CGREG"));
        else if(m_activeAtCommand==QStringLiteral("AT+CREG?")) m_creg=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+CREG"));
        else if(m_activeAtCommand==QStringLiteral("AT+C5GREG?")) m_c5greg=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+C5GREG"));
        else if(m_activeAtCommand==QStringLiteral("AT+CGATT?")){
            const QString v=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+CGATT"));bool ok=false;const int n=v.toInt(&ok);if(ok)m_cgatt=n;
        }else if(m_activeAtCommand==QStringLiteral("AT+CSQ")){
            const QString v=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+CSQ"));bool ok=false;const int n=v.section(QLatin1Char(','),0,0).trimmed().toInt(&ok);if(ok)m_csq=n;
        }else if(m_activeAtCommand==QStringLiteral("AT+COPS?")){
            const QString v=DeviceDiscoveryParser::parseAtTaggedValue(output,QStringLiteral("+COPS"));const AtOperatorInfo op=AtStatusParser::parseOperator(v);if(op.valid){m_operatorName=op.operatorName;m_operatorAccessTechnology=op.accessTechnology;}
        }
        QRegularExpression cme(QStringLiteral("\\+CME ERROR:\\s*(\\d+)"),QRegularExpression::CaseInsensitiveOption);
        auto cm=cme.match(output);if(cm.hasMatch()){
            const int code=cm.captured(1).toInt();
            const QString description=AtStatusParser::cmeErrorText(code);
            m_atErrors<<QStringLiteral("%1：%2").arg(m_activeAtCommand,description);
            if(m_activeAtCommand==QStringLiteral("AT+CPIN?")){m_simStatus=description;m_cpinRaw=QStringLiteral("+CME ERROR: %1 (%2)").arg(code).arg(description);}
        }
        ++m_moduleInfoIndex;
    }
}

void DeviceDiscoveryController::startModuleProbe()
{
    m_moduleProbeAttempted=true;
    m_moduleCandidates=DeviceDiscoveryParser::parseModuleDevices(m_moduleNvramDeviceOutput);
    const QStringList hinted=DeviceDiscoveryParser::parseModuleDevices(m_moduleHintOutput);
    for(const QString& device:hinted) if(!m_moduleCandidates.contains(device)) m_moduleCandidates<<device;
    const QStringList listed=DeviceDiscoveryParser::parseModuleDevices(m_moduleDeviceOutput);
    for(const QString& device:listed) if(!m_moduleCandidates.contains(device)) m_moduleCandidates<<device;
    m_moduleCandidateIndex=0;
    if(m_moduleCandidates.isEmpty()){
        emit progress(QStringLiteral("未发现可用的 ttyUSB/ttyACM 模组控制口，跳过AT识别"));
        finish();
        return;
    }
    m_phase=Phase::ProbeAti;
    emit progress(QStringLiteral("发现%1个候选模组控制口，正在发送ATI确认AT口").arg(m_moduleCandidates.size()));
    runNext();
}

void DeviceDiscoveryController::runNext()
{
    if(!m_running) return;
    if(m_phase==Phase::BaseDiscovery){
        // The route check follows the NVRAM WAN/module inventory. Once it has
        // completed, a missing WAN stops only the AT-port probing; NVRAM module
        // identity is still returned immediately instead of being discarded.
        if(m_index<m_commands.size() && m_commands.at(m_index).contains(QStringLiteral("CONTROL DEVICES"))){
            const DeviceDiscoveryResult base=DeviceDiscoveryParser::buildResult(
                m_wanIfnameOutput,m_wanIpOutput,m_backupWanIpOutput,m_ifconfigOutput,m_routeOutput,
                m_backupWanIfnameOutput,m_wanIfname2Output,m_commWanIpOutput,m_usingBackupCard);
            if(base.wanIfname.isEmpty()){
                emit progress(QStringLiteral("未识别到活动WAN接口，保留NVRAM模组信息并停止AT探测"));
                finish();
                return;
            }
            const QString fastModule=m_usingBackupCard?m_nvramBackupModuleName:(!m_nvramCommName.isEmpty()?m_nvramCommName:(!m_nvramSubmoduleName.isEmpty()?m_nvramSubmoduleName:m_nvramCurrentModuleName));
            if(isPlausibleModuleIdentity(fastModule) && !m_nvramSimStatus.isEmpty()){
                emit progress(QStringLiteral("已从NVRAM快速读取WAN/模组/SIM/信号状态"));
                finish();
                return;
            }
        }
        if(m_index>=m_commands.size()){
            const QString fastModule=m_usingBackupCard?m_nvramBackupModuleName:(!m_nvramCommName.isEmpty()?m_nvramCommName:(!m_nvramSubmoduleName.isEmpty()?m_nvramSubmoduleName:m_nvramCurrentModuleName));
            // NVRAM gives the routine status cards immediately. AT remains the fallback
            // when module identity/SIM state is absent or suspicious.
            if(isPlausibleModuleIdentity(fastModule) && !m_nvramSimStatus.isEmpty()){
                emit progress(QStringLiteral("已从NVRAM快速读取WAN/模组/SIM/信号状态"));
                finish();
            }else startModuleProbe();
            return;
        }
        m_pendingCommand=m_commands.at(m_index++);
        m_client->executeCommand(m_pendingCommand,4500);
        return;
    }
    if(m_phase==Phase::ProbeAti){
        if(m_moduleCandidateIndex>=m_moduleCandidates.size()){finish();return;}
        m_activeModuleDevice=m_moduleCandidates.at(m_moduleCandidateIndex);
        m_activeAtCommand=QStringLiteral("ATI");
        m_pendingCommand=buildAtCommand(m_activeModuleDevice,m_activeAtCommand);
        emit progress(QStringLiteral("尝试模组AT口 %1").arg(m_activeModuleDevice));
        m_client->executeCommand(m_pendingCommand,6500);
        return;
    }
    if(m_phase==Phase::QueryModuleInfo){
        static const QStringList infoCommands={
            QStringLiteral("AT+CGMI"),QStringLiteral("AT+CGMM"),QStringLiteral("AT+CGMR"),
            QStringLiteral("AT+CPIN?"),QStringLiteral("AT+CEREG?"),QStringLiteral("AT+CGREG?"),
            QStringLiteral("AT+CREG?"),QStringLiteral("AT+C5GREG?"),
            QStringLiteral("AT+CGATT?"),QStringLiteral("AT+CSQ"),QStringLiteral("AT+COPS?")
        };
        if(m_moduleInfoIndex>=infoCommands.size()){finish();return;}
        m_activeAtCommand=infoCommands.at(m_moduleInfoIndex);
        m_pendingCommand=buildAtCommand(m_activeModuleDevice,m_activeAtCommand);
        m_client->executeCommand(m_pendingCommand,6500);
    }
}

void DeviceDiscoveryController::finish()
{
    DeviceDiscoveryResult result=DeviceDiscoveryParser::buildResult(
        m_wanIfnameOutput,m_wanIpOutput,m_backupWanIpOutput,m_ifconfigOutput,m_routeOutput,
        m_backupWanIfnameOutput,m_wanIfname2Output,m_commWanIpOutput,m_usingBackupCard);
    result.moduleControlDevice=m_moduleAtResponsive?m_activeModuleDevice:QString();
    result.moduleManufacturer=m_moduleManufacturer;
    QString nvramModule;
    if(m_usingBackupCard && isPlausibleModuleIdentity(m_nvramBackupModuleName))nvramModule=m_nvramBackupModuleName;
    else if(isPlausibleModuleIdentity(m_nvramCommName))nvramModule=m_nvramCommName;
    else if(isPlausibleModuleIdentity(m_nvramSubmoduleName))nvramModule=m_nvramSubmoduleName;
    else if(isPlausibleModuleIdentity(m_nvramCurrentModuleName))nvramModule=m_nvramCurrentModuleName;
    result.moduleModel=!m_moduleModel.isEmpty()?m_moduleModel:nvramModule;
    result.nvramFirmware=m_nvramFirmware;
    result.moduleFirmware=!m_moduleFirmware.isEmpty()?m_moduleFirmware:m_nvramFirmware;
    result.moduleAtResponsive=m_moduleAtResponsive;
    result.moduleProbeAttempted=m_moduleProbeAttempted;
    result.moduleProbeCompleted=m_moduleProbeAttempted;
    result.simStatus=!m_simStatus.isEmpty()?m_simStatus:m_nvramSimStatus;
    result.rsrp=m_nvramRsrp;result.sinr=m_nvramSinr;result.usingBackupCard=m_usingBackupCard;result.nvramNetwork=m_nvramNetwork;
    result.commModuleStatus=m_nvramCommModuleStatus;result.commDialStatus=m_nvramCommDialStatus;result.wanUp=m_nvramWanUp;result.backupWanUp=m_nvramBackupWanUp;
    result.cpinRaw=m_cpinRaw;
    result.cereg=m_cereg;
    result.cgreg=m_cgreg;
    result.creg=m_creg;
    result.c5greg=m_c5greg;
    result.cgatt=m_cgatt;result.csq=m_csq;result.operatorName=m_operatorName;result.operatorAccessTechnology=m_operatorAccessTechnology;result.atErrors=m_atErrors;
    m_running=false;
    m_pendingCommand.clear();
    emit finished(result);
}
