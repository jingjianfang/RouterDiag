#include "LogAnalyzer.h"
#include "AtStatusParser.h"
#include "ConnectivityProbe.h"
#include "NvramSnapshotParser.h"
#include <QRegularExpression>

namespace {
QString lastCap(const QString& text, const QRegularExpression& re, int group=1)
{
    auto it=re.globalMatch(text);
    QString v;
    while(it.hasNext()) v=it.next().captured(group).trimmed();
    return v;
}

bool regOk(const QString& value)
{
    return AtStatusParser::parseRegistration(value).registered();
}

int lastInt(const QString& text,const QRegularExpression& re,int fallback= -1)
{
    const QString value=lastCap(text,re);
    if(value.isEmpty()) return fallback;
    bool ok=false;
    const int n=value.toInt(&ok);
    return ok?n:fallback;
}

QString normalizeSim(const QString& value)
{
    QString v=value.trimmed();
    if(v.startsWith('+')) {
        const int colon=v.indexOf(':');
        if(colon>=0) v=v.mid(colon+1).trimmed();
    }
    return v;
}

bool isUsableWanInterfaceName(const QString& value)
{
    const QString v=value.trimmed();
    if(v.contains(QStringLiteral("nvram get wan_ifname"),Qt::CaseInsensitive) ||
       v.contains(QStringLiteral("wan_ifname="),Qt::CaseInsensitive)) return false;
    return ConnectivityProbe::isUsableWanInterfaceName(v);
}
}

namespace {
QString snapshotFirst(const NvramSnapshot& snapshot,const QStringList& keys)
{
    for(const QString& key:keys){
        const QString value=snapshot.value(key).trimmed();
        if(!value.isEmpty()) return value;
    }
    return {};
}

int snapshotInt(const NvramSnapshot& snapshot,const QStringList& keys,int fallback=-1)
{
    const QString value=snapshotFirst(snapshot,keys);
    bool ok=false;
    const int result=value.toInt(&ok);
    return ok?result:fallback;
}

bool protocolEnabled(const QString& value)
{
    const QString v=value.trimmed().toLower();
    return !v.isEmpty() && v!=QStringLiteral("disabled") && v!=QStringLiteral("disable") &&
           v!=QStringLiteral("off") && v!=QStringLiteral("none") && v!=QStringLiteral("0");
}

bool sameNonEmpty(const QString& a,const QString& b)
{
    return !a.trimmed().isEmpty() && !b.trimmed().isEmpty() &&
           a.trimmed().compare(b.trimmed(),Qt::CaseInsensitive)==0;
}
}

WanStatus LogAnalyzer::analyzeNvramSnapshot(const NvramSnapshot& snapshot)
{
    WanStatus s;
    if(!snapshot.valid) return s;

    s.nvramSnapshotPresent=true;
    s.nvramSnapshotFormat=NvramSnapshotParser::formatName(snapshot.format);
    s.nvramRecordCount=snapshot.recordCount;
    s.evidence<<QStringLiteral("NVRAM配置快照：%1，记录=%2").arg(s.nvramSnapshotFormat).arg(s.nvramRecordCount);

    s.wanProto=snapshotFirst(snapshot,{QStringLiteral("wan_proto"),QStringLiteral("wan_proto_type")});
    s.backupWanProto=snapshotFirst(snapshot,{QStringLiteral("bkup_wan_proto"),QStringLiteral("bkup_wan_proto_type")});
    s.nvramPrimaryWanIp=snapshot.value(QStringLiteral("wan_ipaddr")).trimmed();
    s.backupWanIp=snapshot.value(QStringLiteral("bkup_wan_ipaddr")).trimmed();
    if(s.backupWanIp.isEmpty()) s.backupWanIp=QStringLiteral("0.0.0.0");
    s.commWanIp=snapshot.value(QStringLiteral("comm_wan_ipaddr")).trimmed();
    s.wanUp=snapshotInt(snapshot,{QStringLiteral("wanup")});
    s.backupWanUp=snapshotInt(snapshot,{QStringLiteral("bkupwanup")});
    s.commDialStatus=snapshotInt(snapshot,{QStringLiteral("comm_dial_status")});

    const bool primaryIpUsable=ConnectivityProbe::isUsableWanIpv4(s.nvramPrimaryWanIp);
    const bool backupIpUsable=ConnectivityProbe::isUsableWanIpv4(s.backupWanIp);
    const bool commIpUsable=ConnectivityProbe::isUsableWanIpv4(s.commWanIp);
    const bool primaryProtocol=protocolEnabled(s.wanProto);
    const bool backupProtocol=protocolEnabled(s.backupWanProto);
    const QString primaryIf=snapshotFirst(snapshot,{QStringLiteral("wan_ifname"),QStringLiteral("wan_iface")});
    const QString backupIf=snapshotFirst(snapshot,{QStringLiteral("bkup_wan_ifname"),QStringLiteral("bkup_wan_iface")});
    const bool primaryActive=primaryProtocol && s.wanUp==1 && (primaryIpUsable || (commIpUsable && !backupIpUsable));
    const bool backupActive=backupProtocol && s.backupWanUp==1 && backupIpUsable;

    // Firmware often carries dormant/default bkup_* keys even on a primary-only deployment.
    // Therefore a populated backup protocol alone is not enough to declare a dual-link topology.
    const bool primaryPathPresent=primaryProtocol || primaryActive;
    const bool backupPathPresent=backupProtocol &&
        (!primaryProtocol || backupActive || s.backupWanUp==1 || backupIpUsable || isUsableWanInterfaceName(backupIf));
    s.primaryWanPresent=primaryPathPresent;
    s.backupWanPresent=backupPathPresent;
    if(primaryPathPresent && backupPathPresent) s.wanTopology=QStringLiteral("dual");
    else if(primaryPathPresent) s.wanTopology=QStringLiteral("primary-only");
    else if(backupPathPresent) s.wanTopology=QStringLiteral("backup-only");
    else s.wanTopology=QStringLiteral("unknown");
    s.evidence<<QStringLiteral("WAN拓扑=%1（主=%2，备=%3）")
        .arg(s.wanTopology,primaryPathPresent?QStringLiteral("存在"):QStringLiteral("未确认"),
             backupPathPresent?QStringLiteral("存在"):QStringLiteral("未确认"));

    QString selectedIp;
    if(primaryActive && backupActive){
        if(sameNonEmpty(s.commWanIp,s.backupWanIp) && !sameNonEmpty(s.commWanIp,s.nvramPrimaryWanIp)){
            s.activeWanPath=QStringLiteral("backup");
            selectedIp=s.backupWanIp;
        }else{
            s.activeWanPath=QStringLiteral("primary");
            selectedIp=primaryIpUsable?s.nvramPrimaryWanIp:s.commWanIp;
        }
    }else if(primaryActive){
        s.activeWanPath=QStringLiteral("primary");
        selectedIp=primaryIpUsable?s.nvramPrimaryWanIp:s.commWanIp;
    }else if(backupActive){
        s.activeWanPath=QStringLiteral("backup");
        selectedIp=s.backupWanIp;
    }else{
        s.activeWanPath=QStringLiteral("unknown");
    }

    if(ConnectivityProbe::isUsableWanIpv4(selectedIp)){
        s.wanIp=selectedIp;
        s.wanIpFromNvramSnapshot=true;
        if(s.activeWanPath==QStringLiteral("backup")){
            s.wanIpSource=QStringLiteral("NVRAM活动备用链");
            if(isUsableWanInterfaceName(backupIf)) s.wanIfname=backupIf;
        }else{
            s.wanIpSource=QStringLiteral("NVRAM活动主链");
            if(isUsableWanInterfaceName(primaryIf)) s.wanIfname=primaryIf;
        }
        s.evidence<<QStringLiteral("快照活动WAN=%1，IP=%2，来源=%3").arg(s.activeWanPath,s.wanIp,s.wanIpSource);
    }else{
        s.evidence<<QStringLiteral("快照未满足活动WAN判据：主协议=%1/wanup=%2，备用协议=%3/bkupwanup=%4")
                    .arg(s.wanProto.isEmpty()?QStringLiteral("未知"):s.wanProto).arg(s.wanUp)
                    .arg(s.backupWanProto.isEmpty()?QStringLiteral("未知"):s.backupWanProto).arg(s.backupWanUp);
        if(primaryIpUsable || backupIpUsable)
            s.evidence<<QStringLiteral("存在NVRAM缓存IP，但未作为当前WAN成功证据");
    }

    s.configuredModuleName=snapshotFirst(snapshot,{QStringLiteral("modulename"),QStringLiteral("current_module_name")});
    s.runtimeModuleName=snapshotFirst(snapshot,{QStringLiteral("current_module_real_name"),QStringLiteral("bkup_current_module_real_name"),
                                                QStringLiteral("comm_name"),QStringLiteral("submodulename"),QStringLiteral("current_module_name")});
    s.moduleName=!s.runtimeModuleName.isEmpty()?s.runtimeModuleName:s.configuredModuleName;
    s.moduleIdentityMismatch=!s.configuredModuleName.isEmpty() && !s.runtimeModuleName.isEmpty() &&
                             s.configuredModuleName.compare(s.runtimeModuleName,Qt::CaseInsensitive)!=0;
    s.commModuleStatus=snapshotInt(snapshot,{QStringLiteral("comm_module_status")});
    s.moduleDetected=s.commModuleStatus==1 || !s.runtimeModuleName.isEmpty() || !s.configuredModuleName.isEmpty();
    s.moduleCode=snapshotFirst(snapshot,{QStringLiteral("3gmodule"),QStringLiteral("bkup3gmodule")});
    s.firmware=snapshotFirst(snapshot,{QStringLiteral("comm_swver"),QStringLiteral("comm_softver")});
    s.moduleControlDevice=snapshot.value(QStringLiteral("controldevice")).trimmed();
    if(s.activeWanPath==QStringLiteral("backup"))
        s.radioAccessMode=snapshotFirst(snapshot,{QStringLiteral("bkup_network"),QStringLiteral("comm_network"),QStringLiteral("network")});
    else
        s.radioAccessMode=snapshotFirst(snapshot,{QStringLiteral("comm_network"),QStringLiteral("network"),QStringLiteral("bkup_network")});
    if(!s.moduleName.isEmpty()){
        QString ev=QStringLiteral("快照模组标识：运行=%1").arg(s.moduleName);
        if(!s.configuredModuleName.isEmpty()) ev+=QStringLiteral("，配置=%1").arg(s.configuredModuleName);
        if(s.moduleIdentityMismatch) ev+=QStringLiteral("（标识不一致，仅提示，不直接判故障）");
        s.evidence<<ev;
    }

    const QString rawSim=snapshotFirst(snapshot,{QStringLiteral("comm_sim_card"),QStringLiteral("sim_card"),QStringLiteral("bkup_sim_card")});
    if(rawSim==QStringLiteral("1") || rawSim.compare(QStringLiteral("simok"),Qt::CaseInsensitive)==0 ||
       rawSim.compare(QStringLiteral("READY"),Qt::CaseInsensitive)==0){
        s.simStatus=QStringLiteral("READY");
        s.simStatusFromNvram=true;
        s.simCardRaw=rawSim;
    }else if(rawSim==QStringLiteral("0") || rawSim.compare(QStringLiteral("simfail"),Qt::CaseInsensitive)==0){
        s.simStatus=QStringLiteral("NOT READY");
        s.simStatusFromNvram=true;
        s.simCardRaw=rawSim;
    }

    s.mcc=snapshotFirst(snapshot,{QStringLiteral("comm_mcc"),QStringLiteral("bkup_mc_mcc")});
    s.mnc=snapshotFirst(snapshot,{QStringLiteral("comm_mnc"),QStringLiteral("bkup_mc_mnc")});
    s.lac=snapshotFirst(snapshot,{QStringLiteral("comm_lac"),QStringLiteral("bkup_mc_lac")});
    s.cellId=snapshotFirst(snapshot,{QStringLiteral("comm_cellid"),QStringLiteral("bkup_mc_cellid"),QStringLiteral("comm_eci")});
    s.pci=snapshotInt(snapshot,{QStringLiteral("comm_pci"),QStringLiteral("bkup_Pacific_MonscPCI")});
    s.band=snapshotFirst(snapshot,{QStringLiteral("comm_band"),QStringLiteral("bkup_band")});
    s.earfcn=snapshotInt(snapshot,{QStringLiteral("comm_arfcn"),QStringLiteral("bkup_Pacific_arfcn")});
    s.rssi=snapshotInt(snapshot,{QStringLiteral("comm_rssi"),QStringLiteral("bkup_rssi")},999);
    s.csq=snapshotInt(snapshot,{QStringLiteral("comm_csq")});
    s.rsrp=snapshotInt(snapshot,{QStringLiteral("comm_rsrp"),QStringLiteral("bkup_rsrp")},999);
    s.rsrq=snapshotInt(snapshot,{QStringLiteral("comm_rsrq"),QStringLiteral("bkup_rsrq")},999);
    s.sinr=snapshotInt(snapshot,{QStringLiteral("comm_sinr"),QStringLiteral("bkup_sinr")},999);
    s.operatorName=snapshot.value(QStringLiteral("comm_isp")).trimmed();
    s.apn=s.activeWanPath==QStringLiteral("backup")?snapshot.value(QStringLiteral("bkup_wan_apn")).trimmed():snapshot.value(QStringLiteral("wan_apn")).trimmed();
    if(!s.radioAccessMode.isEmpty())
        s.evidence<<QStringLiteral("NVRAM制式提示=%1（不替代CEREG/CGREG/CREG注册判断）").arg(s.radioAccessMode);

    s.dtsEnabled=snapshotInt(snapshot,{QStringLiteral("dts_en")});
    s.dtsRun=snapshotInt(snapshot,{QStringLiteral("dts_run")});
    s.dtsConStatus=snapshotInt(snapshot,{QStringLiteral("dts_con_status")});
    s.dtsDcuConStatus=snapshotInt(snapshot,{QStringLiteral("dts_dcu_con_status")});
    s.dtsConStatus2=snapshotInt(snapshot,{QStringLiteral("dts_con_status_2")});
    s.dtsDcuConStatus2=snapshotInt(snapshot,{QStringLiteral("dts_dcu_con_status_2")});

    const bool dtsProfile2Connected=s.dtsDcuConStatus2==1 && s.dtsDcuConStatus!=1;
    const bool hasDtsProfile2=snapshot.contains(QStringLiteral("dts_dcuip_2")) || snapshot.contains(QStringLiteral("dts_dcuport_2")) ||
                              s.dtsDcuConStatus2>=0 || s.dtsConStatus2>=0;
    s.dtsActiveProfile=dtsProfile2Connected?2:((s.dtsDcuConStatus==1 || !snapshot.value(QStringLiteral("dts_dcuip")).trimmed().isEmpty())?1:(hasDtsProfile2?2:-1));
    const bool useDts2=s.dtsActiveProfile==2;
    s.dcucom=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_dcucom_2"):QStringLiteral("dts_dcucom")});
    s.dcuIp=snapshot.value(useDts2?QStringLiteral("dts_dcuip_2"):QStringLiteral("dts_dcuip")).trimmed();
    s.dcuPort=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_dcuport_2"):QStringLiteral("dts_dcuport")});
    s.serialBaudrate=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_baudrate2"):QStringLiteral("dts_baudrate1")});
    s.serialDatabit=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_databit2"):QStringLiteral("dts_databit1")});
    s.serialStopbit=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_stopbit2"):QStringLiteral("dts_stopbit1")});
    s.serialParity=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_parity2"):QStringLiteral("dts_parity1")});
    s.serialFlowcontrol=snapshotInt(snapshot,{useDts2?QStringLiteral("dts_flowcontrol2"):QStringLiteral("dts_flowcontrol1")});
    s.dtsStarted=s.dtsRun==1;
    if(s.dtsEnabled>=0 || s.dtsRun>=0 || s.dtsConStatus>=0 || s.dtsDcuConStatus>=0 || s.dtsDcuConStatus2>=0){
        s.evidence<<QStringLiteral("DTS快照：enable=%1 run=%2 p1(con=%3,dcu=%4) p2(con=%5,dcu=%6) active=%7")
                    .arg(s.dtsEnabled).arg(s.dtsRun).arg(s.dtsConStatus).arg(s.dtsDcuConStatus)
                    .arg(s.dtsConStatus2).arg(s.dtsDcuConStatus2).arg(s.dtsActiveProfile);
    }

    return s;
}

WanStatus LogAnalyzer::analyze(const QString& text)
{
    const NvramSnapshot snapshot=NvramSnapshotParser::parseText(text);
    if(snapshot.valid) return analyzeNvramSnapshot(snapshot);

    WanStatus s;
    const QStringList lines=text.split(QRegularExpression("[\\r\\n]+"),Qt::SkipEmptyParts);
    QString currentCmd;
    QStringList currentResponse;

    const QRegularExpression qre("(?:MAIN LINK Q:|4G_MAIN_Q:)\\s*(AT[^\\r\\n]*)",QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression cme("\\+CME ERROR:\\s*(\\d+)",QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression wan1("\\[data=wan_ipaddr\\s+value=([^\\]]+)\\]",QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression wan2("\\[name=\\s*wan_ipaddr\\s+data(?:2)?=\\s*([^\\]]+)\\]",QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression controlDev("CONTROL DEVICES\\s+([^\\s]+)",QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression modelLine("^(N\\d+[A-Za-z0-9_-]*)$",QRegularExpression::CaseInsensitiveOption);

    auto finishAtResponse=[&](const QString& terminalLine){
        if(currentCmd.startsWith("ATI",Qt::CaseInsensitive) && terminalLine.compare("OK",Qt::CaseInsensitive)==0){
            s.moduleAtResponsive=true;
            for(const QString& candidate:currentResponse){
                const QString c=candidate.trimmed();
                auto mm=modelLine.match(c);
                if(mm.hasMatch()) s.moduleName=mm.captured(1);
            }
        }
        if(currentCmd.startsWith("AT+CPIN?",Qt::CaseInsensitive)){
            const auto cmeMatch=cme.match(terminalLine);
            if(cmeMatch.hasMatch()){
                ++s.cpinErrorCount;
                const int code=cmeMatch.captured(1).toInt();
                s.simStatus=AtStatusParser::cmeErrorText(code);
                s.cpinRaw=QStringLiteral("+CME ERROR: %1 (%2)").arg(code).arg(s.simStatus);
            }else if(terminalLine.compare("ERROR",Qt::CaseInsensitive)==0){
                ++s.cpinErrorCount;
                s.cpinRaw=QStringLiteral("ERROR");
            }
            for(const QString& responseLine:currentResponse){
                if(responseLine.contains("+CPIN:",Qt::CaseInsensitive)){
                    s.cpinRaw=responseLine.trimmed();
                    const QString normalized=normalizeSim(responseLine);
                    if(!normalized.isEmpty()) s.simStatus=normalized;
                }
            }
        }
        currentResponse.clear();
        currentCmd.clear();
    };

    for(const QString& raw:lines){
        const QString line=raw.trimmed();
        auto qm=qre.match(line);
        if(qm.hasMatch()){
            currentCmd=qm.captured(1).trimmed();
            currentResponse.clear();
        }else if(!currentCmd.isEmpty() &&
                 !line.startsWith("4G_MAIN_A:",Qt::CaseInsensitive) &&
                 !line.startsWith("MAIN LINK A:",Qt::CaseInsensitive)){
            if(line.compare("OK",Qt::CaseInsensitive)==0 || line.compare("ERROR",Qt::CaseInsensitive)==0 || cme.match(line).hasMatch()){
                finishAtResponse(line);
            }else{
                currentResponse<<line;
            }
        }

        if(line.contains("detected",Qt::CaseInsensitive)||line.contains("This is 4G/LTE Module",Qt::CaseInsensitive))
            s.moduleDetected=true;

        auto dev=controlDev.match(line);
        if(dev.hasMatch()) s.moduleControlDevice=dev.captured(1).trimmed();

        auto cm=cme.match(line);
        if(cm.hasMatch()) s.cmeErrors.append({currentCmd,cm.captured(1).toInt(),line});

        auto w=wan1.match(line);
        if(w.hasMatch()) s.wanIp=w.captured(1).trimmed();
        w=wan2.match(line);
        if(w.hasMatch()) s.wanIp=w.captured(1).trimmed();

        if(line.contains("Using interface",Qt::CaseInsensitive)&&line.contains("ppp0",Qt::CaseInsensitive)){
            s.pppConnected=true;
            s.evidence<<line;
        }
        if((line.startsWith("MAIN LINK Q:",Qt::CaseInsensitive)||line.startsWith("4G_MAIN_Q:",Qt::CaseInsensitive)) &&
           line.contains("ATD*99",Qt::CaseInsensitive)) s.cellularDialSeen=true;
        if(line.contains("process is wan, but wan is not up",Qt::CaseInsensitive)) ++s.wanNotUpCount;
        if(line.contains("Network is unreachable",Qt::CaseInsensitive)) ++s.networkUnreachableCount;
        if(line.contains("no carrier",Qt::CaseInsensitive)||line.contains("link down",Qt::CaseInsensitive)){s.physicalLinkDown=true;++s.physicalLinkDownCount;}
        else if(line.contains("link up",Qt::CaseInsensitive)||line.contains("carrier on",Qt::CaseInsensitive))s.physicalLinkDown=false;
        if(line.contains("DHCP",Qt::CaseInsensitive)&&(line.contains("fail",Qt::CaseInsensitive)||line.contains("timeout",Qt::CaseInsensitive))){s.dhcpFailure=true;++s.dhcpFailureCount;}
        else if(line.contains("DHCP",Qt::CaseInsensitive)&&(line.contains("bound",Qt::CaseInsensitive)||line.contains("lease",Qt::CaseInsensitive)||line.contains("success",Qt::CaseInsensitive)))s.dhcpFailure=false;
        if(line.contains("PPPoE",Qt::CaseInsensitive) &&
           (line.contains("fail",Qt::CaseInsensitive)||line.contains("timeout",Qt::CaseInsensitive)||line.contains("terminated",Qt::CaseInsensitive)||
            line.contains("authentication failed",Qt::CaseInsensitive)||line.contains("no response",Qt::CaseInsensitive)||line.contains("link down",Qt::CaseInsensitive))){
            s.pppoeFailure=true;++s.pppoeFailureCount;
        }else if(line.contains("PPPoE",Qt::CaseInsensitive) &&
                 (line.contains("connected",Qt::CaseInsensitive)||line.contains("session up",Qt::CaseInsensitive)||line.contains("link up",Qt::CaseInsensitive)))s.pppoeFailure=false;
        if(line.contains("wan network failed.",Qt::CaseInsensitive)){s.wanNetworkFailed=true;++s.wanNetworkFailedCount;}
        else if(line.contains("wan is up",Qt::CaseInsensitive)||line.contains("wan network ok",Qt::CaseInsensitive))s.wanNetworkFailed=false;
        if(line.contains("DTS App start..",Qt::CaseInsensitive)) s.dtsStarted=true;
        if(line.contains("south tcp client config connect",Qt::CaseInsensitive)) s.southTcpConfigured=true;
        if(line.contains("tcp client connect ok",Qt::CaseInsensitive)){
            s.southTcpConnected=true;
            s.observedTerminalTransport=QStringLiteral("TCP");
        }

        QString norm=line;
        norm.replace(QRegularExpression("\\s+")," ");
        if(norm.contains("c0 21 01 ",Qt::CaseInsensitive)) ++s.lcpRequestCount;
        if(norm.contains("c0 21 02 ",Qt::CaseInsensitive)) ++s.lcpAckCount;
        if(norm.contains("80 21 01 ",Qt::CaseInsensitive)) ++s.ipcpRequestCount;
        if(norm.contains("80 21 02 ",Qt::CaseInsensitive)) ++s.ipcpAckCount;
        if(norm.contains("80 21 03 ",Qt::CaseInsensitive)) ++s.ipcpNakCount;
    }

    const QString cpin=lastCap(text,QRegularExpression("\\+CPIN:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));
    if(!cpin.isEmpty()){
        s.cpinRaw=QStringLiteral("+CPIN: ")+cpin;
        s.simStatus=normalizeSim(cpin);
    }else if(text.contains("sim_card data= simok",Qt::CaseInsensitive)){
        s.simStatus=QStringLiteral("READY");
    }else if(s.cpinErrorCount>0 && s.simStatus.isEmpty()){
        // Keep a specific +CME ERROR mapping (for example code 10 => SIM未插入)
        // instead of overwriting it with the generic ERROR fallback.
        s.simStatus=QStringLiteral("ERROR");
    }
    s.simCardRaw=lastCap(text,QRegularExpression("\\[name=\\s*sim_card\\s+data=\\s*([^\\]]*)\\]",QRegularExpression::CaseInsensitiveOption));

    s.cereg=lastCap(text,QRegularExpression("\\+CEREG:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));
    s.cgreg=lastCap(text,QRegularExpression("\\+CGREG:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));
    s.c5greg=lastCap(text,QRegularExpression("\\+C5GREG:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));
    s.creg=lastCap(text,QRegularExpression("\\+CREG:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));

    const QString a=lastCap(text,QRegularExpression("\\+CGATT:\\s*([01])",QRegularExpression::CaseInsensitiveOption));
    if(!a.isEmpty()) s.cgatt=a.toInt();
    const QString q=lastCap(text,QRegularExpression("\\+CSQ:\\s*(\\d+)",QRegularExpression::CaseInsensitiveOption));
    if(!q.isEmpty()) s.csq=q.toInt();
    const QString cops=lastCap(text,QRegularExpression("\\+COPS:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));
    if(!cops.isEmpty()){
        const AtOperatorInfo op=AtStatusParser::parseOperator(cops);
        if(op.valid){s.operatorName=op.operatorName;s.operatorMode=op.mode;s.operatorFormat=op.format;s.operatorAccessTechnology=op.accessTechnology;}
    }

    QString r=lastCap(text,QRegularExpression("(?:^|[^A-Za-z0-9])(?:5g_|nr_|lte_|ss[-_ ]?)?rsrp(?:\\]|\\s|[:=])+[^-\\d]{0,16}(-?\\d+)",QRegularExpression::CaseInsensitiveOption));
    if(!r.isEmpty()) s.rsrp=r.toInt();
    QString rr=lastCap(text,QRegularExpression("(?:^|[^A-Za-z0-9])(?:5g_|nr_|lte_|ss[-_ ]?)?rsrq(?:\\]|\\s|[:=])+[^-\\d]{0,16}(-?\\d+)",QRegularExpression::CaseInsensitiveOption));
    if(!rr.isEmpty()) s.rsrq=rr.toInt();
    QString si=lastCap(text,QRegularExpression("(?:^|[^A-Za-z0-9])(?:5g_|nr_|lte_|ss[-_ ]?)?sinr(?:\\]|\\s|[:=])+[^-\\d]{0,16}(-?\\d+)",QRegularExpression::CaseInsensitiveOption));
    if(!si.isEmpty()) s.sinr=si.toInt();

    s.mcc=lastCap(text,QRegularExpression("mcc\\[[^\\]]*\\]\\s*=\\s*([^\\s]+)",QRegularExpression::CaseInsensitiveOption));
    s.mnc=lastCap(text,QRegularExpression("mnc\\[[^\\]]*\\]\\s*=\\s*([^\\s]+)",QRegularExpression::CaseInsensitiveOption));
    s.lac=lastCap(text,QRegularExpression("(?:Get lac:|mc_lac[^=]*=)\\s*([^\\s]+)",QRegularExpression::CaseInsensitiveOption));
    s.cellId=lastCap(text,QRegularExpression("(?:Get cellID:|cellid[^=]*=)\\s*([^\\s]+)",QRegularExpression::CaseInsensitiveOption));
    s.pci=lastInt(text,QRegularExpression("(?:Get PCI:|pci[^=]*=)\\s*(-?\\d+)",QRegularExpression::CaseInsensitiveOption));
    s.band=lastCap(text,QRegularExpression("Get BAND:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));
    s.earfcn=lastInt(text,QRegularExpression("(?:Get EARFCN:|arfcn[^=]*=)\\s*(-?\\d+)",QRegularExpression::CaseInsensitiveOption));
    s.rssi=lastInt(text,QRegularExpression("(?:Get rssi:|\\[name=\\s*rssi\\s+data=)\\s*(-?\\d+)",QRegularExpression::CaseInsensitiveOption),999);

    s.apn=lastCap(text,QRegularExpression("AT\\+CGDCONT=\\d+,\"[^\"]+\",\"([^\"]+)\"",QRegularExpression::CaseInsensitiveOption));

    QString parsedModule=lastCap(text,QRegularExpression("\\[name=\\s*current_module_real_name\\s+data=\\s*([^\\]]+)\\]",QRegularExpression::CaseInsensitiveOption));
    if(parsedModule.isEmpty()) parsedModule=lastCap(text,QRegularExpression("\\[name=\\s*modulename\\s+data=\\s*([^\\]]+)\\]",QRegularExpression::CaseInsensitiveOption));
    if(parsedModule.isEmpty()) parsedModule=lastCap(text,QRegularExpression("([^\\s]+)\\s+detected",QRegularExpression::CaseInsensitiveOption));
    if(s.moduleName.isEmpty() && !parsedModule.isEmpty()) s.moduleName=parsedModule;

    s.moduleCode=lastCap(text,QRegularExpression("(?:module \\[|3gmodule data=\\s*)(\\d+)",QRegularExpression::CaseInsensitiveOption));
    s.firmware=lastCap(text,QRegularExpression("\\+CGMR:\\s*([^\\r\\n]+)",QRegularExpression::CaseInsensitiveOption));

    QString wanIfnameCandidate=lastCap(text,QRegularExpression(QStringLiteral(R"(wanface=([^\s]+))"),QRegularExpression::CaseInsensitiveOption));
    if(!isUsableWanInterfaceName(wanIfnameCandidate))
        wanIfnameCandidate=lastCap(text,QRegularExpression(QStringLiteral(R"(\[name=\s*wan_ifname\s+data=\s*([^\]]+)\])"),QRegularExpression::CaseInsensitiveOption));
    if(!isUsableWanInterfaceName(wanIfnameCandidate))
        wanIfnameCandidate=lastCap(text,QRegularExpression(QStringLiteral(R"(\$\s*nvram get wan_ifname\s*[\r\n]+\s*([^\r\n#$>]+))"),QRegularExpression::CaseInsensitiveOption));
    if(isUsableWanInterfaceName(wanIfnameCandidate)) s.wanIfname=wanIfnameCandidate.trimmed();

    if(s.wanIp==QStringLiteral("0.0.0.0")){
        const QString direct=lastCap(text,QRegularExpression("\\$\\s*nvram get wan_ipaddr\\s*[\\r\\n]+\\s*((?:\\d{1,3}\\.){3}\\d{1,3})",QRegularExpression::CaseInsensitiveOption));
        if(!direct.isEmpty()) s.wanIp=direct;
    }
    s.backupWanIp=lastCap(text,QRegularExpression(QStringLiteral(R"((?:\[name=\s*bkup_wan_ipaddr\s+(?:data|value)=\s*|\$\s*nvram get bkup_wan_ipaddr\s*[\r\n]+\s*)((?:\d{1,3}\.){3}\d{1,3}))"),QRegularExpression::CaseInsensitiveOption));
    if(s.backupWanIp.isEmpty())s.backupWanIp=QStringLiteral("0.0.0.0");

    if(s.wanIfname.isEmpty()&&s.pppConnected) s.wanIfname=QStringLiteral("ppp0");

    s.dialFinish=lastInt(text,QRegularExpression("\\[name=\\s*DialFinish\\s+data=\\s*(-?\\d+)\\s*\\]",QRegularExpression::CaseInsensitiveOption));
    s.dcucom=lastInt(text,QRegularExpression("(?:^|[\\r\\n])\\s*dcucom=(\\d+)",QRegularExpression::MultilineOption|QRegularExpression::CaseInsensitiveOption));
    auto dcu=QRegularExpression("dcu_ip=([^,\\s]+)\\s*,\\s*dcu_port=(\\d+)",QRegularExpression::CaseInsensitiveOption).match(text);
    if(dcu.hasMatch()){
        s.dcuIp=dcu.captured(1).trimmed();
        s.dcuPort=dcu.captured(2).toInt();
    }
    s.serialBaudrate=lastInt(text,QRegularExpression("serial1 baudrate=(\\d+)",QRegularExpression::CaseInsensitiveOption));
    auto serial=QRegularExpression("databit=(\\d+)\\s*,\\s*stopbit=(\\d+)\\s*,\\s*parity=(\\d+)\\s*,\\s*flowcontrol=(\\d+)",QRegularExpression::CaseInsensitiveOption).match(text);
    if(serial.hasMatch()){
        s.serialDatabit=serial.captured(1).toInt();
        s.serialStopbit=serial.captured(2).toInt();
        s.serialParity=serial.captured(3).toInt();
        s.serialFlowcontrol=serial.captured(4).toInt();
    }

    s.tailLines=lines.mid(qMax(0,lines.size()-10));
    for(const CmeErrorRecord& error:s.cmeErrors){
        s.evidence<<QStringLiteral("%1：%2").arg(error.command,AtStatusParser::cmeErrorText(error.code));
    }
    if(regOk(s.cereg)||regOk(s.cgreg)||regOk(s.c5greg)||regOk(s.creg)) s.evidence<<QStringLiteral("registered");
    return s;
}
