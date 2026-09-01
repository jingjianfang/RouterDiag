#include "DiagnosisEngine.h"
#include "AtStatusParser.h"
#include "ConnectivityProbe.h"
#include <QRegularExpression>

namespace {

int registrationStatus(const QString& value)
{
    const AtRegistrationInfo info=AtStatusParser::parseRegistration(value);
    return info.valid?info.status:-1;
}

bool registeredValue(const QString& value)
{
    return AtStatusParser::parseRegistration(value).registered();
}

QString registrationEvidence(const QString& name,const QString& value)
{
    if(value.trimmed().isEmpty())return {};
    const AtRegistrationInfo info=AtStatusParser::parseRegistration(value);
    if(!info.valid)return QStringLiteral("%1=%2").arg(name,value);
    QString text=QStringLiteral("%1=%2（%3").arg(name,value,AtStatusParser::registrationStatusText(info.status));
    if(info.accessTechnology>=0)text+=QStringLiteral("，%1").arg(AtStatusParser::accessTechnologyText(info.accessTechnology));
    if(info.rejectCause>=0){
        const QString cause=AtStatusParser::rejectCauseText(info.rejectCause);
        text+=QStringLiteral("，reject=%1").arg(info.rejectCause);
        if(!cause.isEmpty())text+=QStringLiteral("(%1)").arg(cause);
    }
    text+=QLatin1Char('）');
    return text;
}

bool anyRegistrationEvidence(const WanStatus& s)
{
    return !s.cereg.isEmpty() || !s.cgreg.isEmpty() || !s.c5greg.isEmpty() || !s.creg.isEmpty();
}

AtRegistrationSelection primaryRegistration(const WanStatus& s)
{
    return AtStatusParser::preferredRegistration(s.c5greg,s.cereg,s.cgreg,s.creg,s.operatorAccessTechnology);
}

QStringList allRegistrationEvidence(const WanStatus& s,const QString& primaryName=QString())
{
    QStringList ev;
    const QList<QPair<QString,QString>> regs={{QStringLiteral("C5GREG"),s.c5greg},{QStringLiteral("CEREG"),s.cereg},{QStringLiteral("CGREG"),s.cgreg},{QStringLiteral("CREG"),s.creg}};
    for(const auto& item:regs){
        const QString text=registrationEvidence(item.first,item.second);
        if(!text.isEmpty())ev<<(item.first==primaryName?QStringLiteral("主注册域: %1").arg(text):text);
    }
    return ev;
}

QString wanTopologyText(const WanStatus& s)
{
    if(s.wanTopology==QStringLiteral("primary-only")) return QStringLiteral("仅主链路");
    if(s.wanTopology==QStringLiteral("backup-only")) return QStringLiteral("仅备链路");
    if(s.wanTopology==QStringLiteral("dual")) return QStringLiteral("主备双链");
    return QStringLiteral("拓扑未确认");
}

QStringList wanSnapshotReviewSuggestions(const WanStatus& s)
{
    if(s.wanTopology==QStringLiteral("primary-only"))
        return {QStringLiteral("在线读取主链路接口IPv4、carrier/operstate和默认路由"),QStringLiteral("必要时再做主站 Ping/TCP 抓包验证")};
    if(s.wanTopology==QStringLiteral("backup-only"))
        return {QStringLiteral("在线读取备链路接口IPv4、carrier/operstate和默认路由"),QStringLiteral("不要因主WAN为空或disabled把仅备部署误判为故障")};
    if(s.wanTopology==QStringLiteral("dual"))
        return {QStringLiteral("在线读取主备两侧接口状态，并用默认路由确认当前实际出口"),QStringLiteral("仅在主备双链场景检查切换/优先级策略")};
    return {QStringLiteral("在线读取当前接口IPv4、carrier/operstate和默认路由"),QStringLiteral("先确认现场是仅主、仅备还是主备双链")};
}

QStringList signalEvidence(const WanStatus& s)
{
    QStringList ev;
    if(s.rsrp!=999)ev<<QStringLiteral("RSRP=%1 dBm").arg(s.rsrp);
    if(s.rsrq!=999)ev<<QStringLiteral("RSRQ=%1 dB").arg(s.rsrq);
    if(s.sinr!=999)ev<<QStringLiteral("SINR=%1 dB").arg(s.sinr);
    if(s.rssi!=999)ev<<QStringLiteral("RSSI=%1 dBm").arg(s.rssi);
    if(s.csq>=0)ev<<QStringLiteral("CSQ=%1").arg(s.csq);
    if(!s.operatorName.isEmpty()){
        QString op=QStringLiteral("运营商=%1").arg(s.operatorName);
        if(s.operatorAccessTechnology>=0)op+=QStringLiteral("（%1）").arg(AtStatusParser::accessTechnologyText(s.operatorAccessTechnology));
        ev<<op;
    }
    if(!s.radioAccessMode.isEmpty()) ev<<QStringLiteral("NVRAM制式提示=%1（不等同于当前注册成功）").arg(s.radioAccessMode);

    // Only add a qualitative hint when values look like direct engineering units.
    // If a module reports encoded/vendor-specific values, retain the raw evidence above instead of guessing.
    const bool rsrpPlausible=s.rsrp>=-160 && s.rsrp<=-40;
    const bool sinrPlausible=s.sinr>=-30 && s.sinr<=50;
    if(rsrpPlausible && sinrPlausible){
        if(s.rsrp>=-100 && s.sinr<5)
            ev<<QStringLiteral("无线指标提示：RSRP覆盖功率尚可，但SINR偏低，可能存在较强干扰/噪声；不能简单归因于信号弱");
        else if(s.rsrp<=-110)
            ev<<QStringLiteral("无线指标提示：RSRP偏低，覆盖功率可能不足；仍需结合SINR/RSRQ及注册状态判断");
        else if(s.sinr<0)
            ev<<QStringLiteral("无线指标提示：SINR较低，当前无线干扰/噪声环境较差");
        else if(s.rsrp>=-100 && s.sinr>=10)
            ev<<QStringLiteral("无线指标提示：RSRP与SINR均有较好工程参考值，若仍注册失败不宜优先归因于弱信号");
    }else if(rsrpPlausible && s.rsrp<=-110){
        ev<<QStringLiteral("无线指标提示：RSRP偏低；需继续结合RSRQ/SINR或其它模组信号指标判断");
    }else if(sinrPlausible && s.sinr<0){
        ev<<QStringLiteral("无线指标提示：SINR较低；可能存在较强干扰/噪声");
    }
    return ev;
}

LayerDiagnosis layer(QString name,LayerState state,Confidence confidence,QString conclusion,
                     QStringList evidence={},QStringList suggestions={})
{
    LayerDiagnosis d;
    d.layer=std::move(name);
    d.state=state;
    d.confidence=confidence;
    d.conclusion=std::move(conclusion);
    d.evidence=std::move(evidence);
    d.suggestions=std::move(suggestions);
    return d;
}

DiagnosisResult summary(QString type,DiagnosisSeverity sev,QString conclusion,QStringList suggestions,const WanStatus& s)
{
    DiagnosisResult d;
    d.type=std::move(type);
    d.severity=sev;
    d.conclusion=std::move(conclusion);
    d.suggestions=std::move(suggestions);
    d.evidence=s.evidence;
    return d;
}
}

QList<LayerDiagnosis> DiagnosisEngine::diagnoseWanLayers(const WanStatus& s)
{
    QList<LayerDiagnosis> out;

    if(s.moduleAtResponsive){
        QStringList ev{QStringLiteral("AT 通道有正常响应")};
        if(!s.moduleName.isEmpty()) ev<<QStringLiteral("模组型号: %1").arg(s.moduleName);
        if(!s.firmware.isEmpty()) ev<<QStringLiteral("固件版本: %1").arg(s.firmware);
        if(!s.moduleControlDevice.isEmpty()) ev<<QStringLiteral("模组控制口: %1").arg(s.moduleControlDevice);
        out<<layer(QStringLiteral("CELLULAR_MODULE"),LayerState::Normal,Confidence::High,
                   QStringLiteral("模组工作正常：已检测到模组并获得有效 AT 响应"),ev);
    }else if(s.moduleDetected || !s.moduleName.isEmpty()){
        QStringList ev;
        if(!s.moduleName.isEmpty())ev<<QStringLiteral("模组标识=%1").arg(s.moduleName);
        if(!s.configuredModuleName.isEmpty())ev<<QStringLiteral("配置标识=%1").arg(s.configuredModuleName);
        if(s.commModuleStatus>=0)ev<<QStringLiteral("comm_module_status=%1").arg(s.commModuleStatus);
        if(s.moduleIdentityMismatch)ev<<QStringLiteral("配置标识与运行标识不同；该现象可能是模组系列/子型号映射，不直接判故障");
        if(!s.nvramSnapshotPresent && s.commModuleStatus==1 && !s.moduleName.isEmpty())
            out<<layer(QStringLiteral("CELLULAR_MODULE"),LayerState::Normal,Confidence::Medium,
                       QStringLiteral("NVRAM实时状态显示模组工作中；未执行 AT 实时复核"),ev);
        else
            out<<layer(QStringLiteral("CELLULAR_MODULE"),LayerState::Warning,Confidence::Medium,
                       s.nvramSnapshotPresent?QStringLiteral("配置快照显示已识别模组，但缺少实时 AT 应答，不能确认当前 AT 通讯稳定"):
                                              QStringLiteral("已检测到模组，但当前日志缺少完整 AT 响应证据，暂不能确认 AT 通讯稳定"),ev);
    }else if(s.moduleProbeCompleted){
        out<<layer(QStringLiteral("CELLULAR_MODULE"),LayerState::Error,Confidence::High,
                   QStringLiteral("模组探测已完成：未从候选 AT 控制口获得有效响应"),{},
                   {QStringLiteral("检查模组供电、USB枚举和AT控制口"),QStringLiteral("确认控制口未被其它进程占用")});
    }else{
        out<<layer(QStringLiteral("CELLULAR_MODULE"),LayerState::NotTested,Confidence::Low,
                   QStringLiteral("尚未完成模组 AT 探测，当前不能据此判断未安装或故障"));
    }

    if(s.simStatus.compare(QStringLiteral("READY"),Qt::CaseInsensitive)==0 ||
       s.simCardRaw.compare(QStringLiteral("simok"),Qt::CaseInsensitive)==0){
        const Confidence confidence=s.simStatusFromNvram?Confidence::Medium:Confidence::High;
        const QString conclusion=s.simStatusFromNvram?
            (s.nvramSnapshotPresent?QStringLiteral("配置快照显示 SIM 已识别；建议用 AT+CPIN? 实时复核"):
                                    QStringLiteral("NVRAM实时状态显示 SIM 已识别；未执行 AT+CPIN? 实时复核")):
            QStringLiteral("SIM 卡正常：模组已识别 SIM 卡，CPIN 状态已就绪");
        out<<layer(QStringLiteral("SIM"),LayerState::Normal,confidence,conclusion,
                   {s.cpinRaw.isEmpty()?(s.simStatusFromNvram?QStringLiteral("NVRAM SIM=READY"):QStringLiteral("SIM=READY")):s.cpinRaw});
    }else if(s.cpinErrorCount>0 || s.simStatus.compare(QStringLiteral("ERROR"),Qt::CaseInsensitive)==0 ||
             s.simStatus.contains(QStringLiteral("NOT READY"),Qt::CaseInsensitive) ||
             s.simStatus.contains(QStringLiteral("SIM PIN"),Qt::CaseInsensitive) || s.simStatus.contains(QStringLiteral("SIM PUK"),Qt::CaseInsensitive) ||
             s.simStatus.contains(QStringLiteral("未插入"),Qt::CaseInsensitive) || s.simStatus.contains(QStringLiteral("故障"),Qt::CaseInsensitive) ||
             s.simStatus.contains(QStringLiteral("需要SIM"),Qt::CaseInsensitive)){
        QStringList ev;
        if(!s.simStatus.isEmpty())ev<<QStringLiteral("SIM状态=%1").arg(s.simStatus);
        if(!s.cpinRaw.isEmpty())ev<<s.cpinRaw;
        if(s.cpinErrorCount>0) ev<<QStringLiteral("AT+CPIN? 上下文 ERROR 次数: %1").arg(s.cpinErrorCount);
        if(!s.simCardRaw.isEmpty()) ev<<QStringLiteral("sim_card=%1").arg(s.simCardRaw);
        out<<layer(QStringLiteral("SIM"),LayerState::Error,s.simStatusFromNvram?Confidence::Medium:Confidence::High,
                   s.simStatusFromNvram?QStringLiteral("配置快照显示 SIM 未就绪；需要 AT+CPIN? 实时复核"):
                                         QStringLiteral("SIM 卡异常：模组可响应 AT 指令，但 SIM 卡未被正确识别或尚未就绪"),ev,
                   {QStringLiteral("检查 SIM 卡是否插入及方向"),QStringLiteral("检查卡座接触或更换 SIM 卡验证")});
    }else{
        out<<layer(QStringLiteral("SIM"),LayerState::Unknown,Confidence::Low,
                   QStringLiteral("当前日志缺少 CPIN/SIM 状态证据，暂不能确认 SIM 卡状态"));
    }

    const AtRegistrationSelection reg=primaryRegistration(s);
    if(reg.valid() && reg.info.registered()){
        QStringList ev=allRegistrationEvidence(s,reg.source);ev.append(signalEvidence(s));
        out<<layer(QStringLiteral("REGISTRATION"),LayerState::Normal,Confidence::High,
                   QStringLiteral("蜂窝网络注册正常：主注册域 %1=%2").arg(reg.source,AtStatusParser::registrationStatusText(reg.info.status)),ev);
    }else if(reg.valid() && out[1].state==LayerState::Normal){
        QStringList ev=allRegistrationEvidence(s,reg.source);ev.append(signalEvidence(s));
        QString conclusion;
        if(reg.info.limitedRegistration())
            conclusion=QStringLiteral("网络仅处于有限注册状态：%1=%2，当前数据业务能力受限").arg(reg.source,AtStatusParser::registrationStatusText(reg.info.status));
        else
            conclusion=QStringLiteral("蜂窝网络注册异常：主注册域 %1 状态为%2").arg(reg.source,AtStatusParser::registrationStatusText(reg.info.status));
        if(reg.info.rejectCause>=0){
            conclusion+=QStringLiteral("，拒绝原因码=%1").arg(reg.info.rejectCause);
            const QString cause=AtStatusParser::rejectCauseText(reg.info.rejectCause);if(!cause.isEmpty())conclusion+=QStringLiteral("（%1）").arg(cause);
        }
        out<<layer(QStringLiteral("REGISTRATION"),LayerState::Error,Confidence::High,conclusion,ev,
                   {QStringLiteral("检查运营商网络及SIM卡业务状态"),QStringLiteral("结合 RSRP/RSRQ/SINR、CSQ/RSSI、制式/频段及现场覆盖综合判断")});
    }else if(out[1].state==LayerState::Error){
        out<<layer(QStringLiteral("REGISTRATION"),LayerState::NotTested,Confidence::High,
                   QStringLiteral("SIM 卡尚未就绪，蜂窝网络注册阶段暂不具备有效判定条件"));
    }else if(!s.nvramSnapshotPresent && out[1].state==LayerState::Normal && s.commDialStatus==1 &&
             ConnectivityProbe::isUsableWanIpv4(s.wanIp) && !s.radioAccessMode.trimmed().isEmpty() &&
             !s.radioAccessMode.contains(QStringLiteral("NONE"),Qt::CaseInsensitive)){
        QStringList ev{QStringLiteral("comm_dial_status=1"),QStringLiteral("comm_network=%1").arg(s.radioAccessMode),QStringLiteral("WAN IP=%1").arg(s.wanIp)};
        ev.append(signalEvidence(s));
        out<<layer(QStringLiteral("REGISTRATION"),LayerState::Normal,Confidence::Medium,
                   QStringLiteral("NVRAM实时状态显示蜂窝数据已入网；未执行 CEREG/CGREG/CREG 实时复核"),ev);
    }else if(anyRegistrationEvidence(s)){
        out<<layer(QStringLiteral("REGISTRATION"),LayerState::Unknown,Confidence::Medium,
                   QStringLiteral("已收到网络注册相关 AT 输出，但未能结构化确认当前主注册域"),allRegistrationEvidence(s));
    }else{
        out<<layer(QStringLiteral("REGISTRATION"),LayerState::Unknown,Confidence::Low,
                   s.nvramSnapshotPresent?QStringLiteral("配置快照虽包含制式/运营商提示，但缺少 CEREG/CGREG/CREG/C5GREG 实时注册证据，不能据此判定已注册"):
                                          QStringLiteral("当前日志缺少 CEREG/CGREG/CREG/C5GREG 等注册状态证据，暂不能判断网络注册结果"));
    }

    const bool currentWanFault=s.physicalLinkDown||s.dhcpFailure||s.pppoeFailure||s.wanNetworkFailed||(s.wanInterfaceStateKnown&&!s.wanInterfaceUp);
    if(currentWanFault){
        QStringList ev;
        if(s.physicalLinkDown)ev<<QStringLiteral("当前链路状态=down/no carrier");
        if(s.dhcpFailure)ev<<QStringLiteral("当前DHCP失败");
        if(s.pppoeFailure)ev<<QStringLiteral("当前PPPoE失败");
        if(s.wanNetworkFailed)ev<<QStringLiteral("当前WAN网络失败");
        if(s.wanInterfaceStateKnown&&!s.wanInterfaceUp)ev<<QStringLiteral("当前WAN接口 %1 处于DOWN状态").arg(s.wanIfname.isEmpty()?QStringLiteral("--"):s.wanIfname);
        if(ConnectivityProbe::isUsableWanIpv4(s.wanIp))ev<<QStringLiteral("仍保留旧/缓存WAN IP=%1（不能覆盖当前链路故障）").arg(s.wanIp);
        out<<layer(QStringLiteral("WAN"),LayerState::Error,Confidence::High,
                   QStringLiteral("WAN当前状态异常：存在明确的链路/地址获取/拨号失败证据"),ev,
                   {QStringLiteral("先处理当前链路或拨号故障，再使用WAN IP判断网络是否恢复")});
    }else if(ConnectivityProbe::isUsableWanIpv4(s.wanIp)){
        QStringList ev{QStringLiteral("WAN IP=%1").arg(s.wanIp)};
        if(s.nvramSnapshotPresent && s.wanIpFromNvramSnapshot){
            ev<<QStringLiteral("部署拓扑=%1").arg(wanTopologyText(s));
            ev<<QStringLiteral("配置快照活动链=%1").arg(s.activeWanPath.isEmpty()?QStringLiteral("unknown"):s.activeWanPath);
            if(s.primaryWanPresent && !s.wanProto.isEmpty())ev<<QStringLiteral("主WAN协议=%1, wanup=%2").arg(s.wanProto).arg(s.wanUp);
            if(s.backupWanPresent && !s.backupWanProto.isEmpty())ev<<QStringLiteral("备用WAN协议=%1, bkupwanup=%2").arg(s.backupWanProto).arg(s.backupWanUp);
            if(s.commDialStatus>=0)ev<<QStringLiteral("comm_dial_status=%1").arg(s.commDialStatus);
            if(!s.wanIfname.isEmpty())ev<<QStringLiteral("配置接口=%1").arg(s.wanIfname);
            out<<layer(QStringLiteral("WAN"),LayerState::Warning,Confidence::Medium,
                       QStringLiteral("配置快照显示%1中的%2具有活动IP，但这不是实时接口/默认路由证据，需在线复核")
                           .arg(wanTopologyText(s),s.activeWanPath==QStringLiteral("backup")?QStringLiteral("备用WAN"):QStringLiteral("主WAN")),ev,
                       wanSnapshotReviewSuggestions(s));
            return out;
        }
        if(!s.wanIfname.isEmpty())ev<<QStringLiteral("WAN 接口=%1").arg(s.wanIfname);
        if(s.wanInterfaceStateKnown)ev<<QStringLiteral("接口状态=%1").arg(s.wanInterfaceUp?QStringLiteral("UP"):QStringLiteral("DOWN"));
        if(s.cgatt==1)ev<<QStringLiteral("CGATT=1");
        if(s.defaultRouteChecked){
            if(s.defaultRoutePresent){
                QString route=QStringLiteral("默认路由存在");
                if(!s.defaultGateway.isEmpty())route+=QStringLiteral("，网关=%1").arg(s.defaultGateway);
                if(!s.defaultRouteInterface.isEmpty())route+=QStringLiteral("，出口=%1").arg(s.defaultRouteInterface);
                ev<<route;
                out<<layer(QStringLiteral("WAN"),LayerState::Normal,Confidence::High,
                           QStringLiteral("WAN 网络正常：接口无明确故障、具有有效 WAN IP 且存在默认路由"),ev);
            }else{
                ev<<QStringLiteral("未发现默认路由");
                out<<layer(QStringLiteral("WAN"),LayerState::Warning,Confidence::High,
                           QStringLiteral("WAN 已获得有效 IP，但当前未发现默认路由，不能判定公网数据链路完整可用"),ev,
                           {QStringLiteral("检查默认路由、策略路由和拨号脚本是否正确下发路由")});
            }
        }else{
            out<<layer(QStringLiteral("WAN"),LayerState::Normal,Confidence::Medium,
                       QStringLiteral("WAN 已获得有效 IP，当前未见明确链路故障；默认路由尚未核验"),ev);
        }
    }else if(s.cellularDialSeen && s.pppConnected && s.ipcpRequestCount>0 && s.ipcpAckCount==0){
        out<<layer(QStringLiteral("WAN"),LayerState::Error,Confidence::High,
                   QStringLiteral("WAN 建链异常：蜂窝 PPP 链路已建立，但 IPCP 地址协商未完成，尚未获得可用 WAN IP"),
                   {QStringLiteral("IPCP Request=%1, Ack=%2").arg(s.ipcpRequestCount).arg(s.ipcpAckCount)},
                   {QStringLiteral("核对 APN/PDP 类型"),QStringLiteral("确认运营商是否分配 IP")});
    }else if(out[2].state==LayerState::Error){
        QStringList ev{QStringLiteral("WAN IP=%1").arg(s.wanIp)};
        if(s.networkUnreachableCount>0)ev<<QStringLiteral("Network is unreachable 次数=%1").arg(s.networkUnreachableCount);
        out<<layer(QStringLiteral("WAN"),LayerState::NotTested,Confidence::High,
                   QStringLiteral("上游蜂窝网络注册失败，WAN/IP 阶段暂不具备有效测试条件"),ev,
                   {QStringLiteral("先处理蜂窝网络注册问题，再验证 WAN 地址获取")});
    }else if(s.cgatt==0){
        out<<layer(QStringLiteral("WAN"),LayerState::Error,Confidence::High,
                   QStringLiteral("WAN 建链异常：蜂窝数据附着未成功，当前未获得有效 WAN IP"),{QStringLiteral("CGATT=0")});
    }else if(s.cgatt==1 || s.pppConnected || (reg.valid()&&reg.info.registered())){
        const QString shown=s.wanIp.trimmed().isEmpty()?QStringLiteral("未获取"):s.wanIp.trimmed();
        QStringList ev;
        if(reg.valid())ev<<QStringLiteral("蜂窝注册=%1/%2").arg(reg.source,AtStatusParser::registrationStatusText(reg.info.status));
        if(s.cgatt>=0)ev<<QStringLiteral("CGATT=%1").arg(s.cgatt);
        ev<<QStringLiteral("WAN IP=%1（无效/未分配）").arg(shown);
        out<<layer(QStringLiteral("WAN"),LayerState::Warning,Confidence::High,
                   QStringLiteral("蜂窝网络已注册/附着，但尚未获得有效 WAN IP（当前=%1），数据业务链路未完成").arg(shown),ev,
                   {QStringLiteral("检查 APN、PDP/PDN 激活、拨号状态和认证"),QStringLiteral("确认运营商数据业务是否开通并实际分配地址")});
    }else if(s.nvramSnapshotPresent){
        QStringList ev{QStringLiteral("部署拓扑=%1").arg(wanTopologyText(s))};
        if(s.primaryWanPresent || s.wanTopology==QStringLiteral("unknown"))
            ev<<QStringLiteral("主WAN: proto=%1 wanup=%2 ip=%3")
                .arg(s.wanProto.isEmpty()?QStringLiteral("未知"):s.wanProto).arg(s.wanUp)
                .arg(s.nvramPrimaryWanIp.isEmpty()?QStringLiteral("未记录"):s.nvramPrimaryWanIp);
        if(s.backupWanPresent || s.wanTopology==QStringLiteral("unknown"))
            ev<<QStringLiteral("备用WAN: proto=%1 bkupwanup=%2 ip=%3")
                .arg(s.backupWanProto.isEmpty()?QStringLiteral("未知"):s.backupWanProto).arg(s.backupWanUp)
                .arg(s.backupWanIp.isEmpty()?QStringLiteral("未记录"):s.backupWanIp);
        out<<layer(QStringLiteral("WAN"),LayerState::Warning,Confidence::Medium,
                   QStringLiteral("%1配置快照未能确认当前活动 WAN；缓存地址或单个 up 标志不足以证明链路可用").arg(wanTopologyText(s)),ev,
                   wanSnapshotReviewSuggestions(s));
    }else{
        out<<layer(QStringLiteral("WAN"),LayerState::Unknown,Confidence::Low,
                   QStringLiteral("当前日志缺少足够的拨号/附着/IP 证据，暂不能判断 WAN 建链阶段"));
    }

    return out;
}

DiagnosisResult DiagnosisEngine::diagnose(const WanStatus& s)
{
    // Current explicit failures outrank a stale/cached WAN IP.
    if(s.physicalLinkDown)
        return summary(QStringLiteral("PHYSICAL_LINK_DOWN"),DiagnosisSeverity::Error,QStringLiteral("物理链路断开"),
                       {QStringLiteral("检查网线/天线"),QStringLiteral("确认对端链路")},s);
    if(s.dhcpFailure)
        return summary(QStringLiteral("DHCP_FAILED"),DiagnosisSeverity::Error,QStringLiteral("DHCP 获取 IP 失败"),
                       {QStringLiteral("检查上级 DHCP"),QStringLiteral("检查链路与 VLAN")},s);
    if(s.pppoeFailure)
        return summary(QStringLiteral("PPPOE_FAILED"),DiagnosisSeverity::Error,QStringLiteral("PPPoE 协商失败"),
                       {QStringLiteral("核对宽带账号密码"),QStringLiteral("确认运营商线路")},s);
    if(s.wanNetworkFailed)
        return summary(QStringLiteral("WAN_NETWORK_FAILED"),DiagnosisSeverity::Error,QStringLiteral("WAN 当前网络状态失败"),
                       {QStringLiteral("检查当前WAN接口状态、默认路由和上游链路")},s);
    if(s.wanInterfaceStateKnown && !s.wanInterfaceUp)
        return summary(QStringLiteral("WAN_INTERFACE_DOWN"),DiagnosisSeverity::Error,QStringLiteral("WAN接口当前处于DOWN状态；缓存IP不能作为网络正常依据"),
                       {QStringLiteral("检查接口carrier/operstate和上游链路")},s);

    if(ConnectivityProbe::isUsableWanIpv4(s.wanIp)){
        if(s.nvramSnapshotPresent && s.wanIpFromNvramSnapshot)
            return summary(QStringLiteral("WAN_SNAPSHOT_ACTIVE_HINT"),DiagnosisSeverity::Warning,
                           QStringLiteral("配置快照显示活动WAN具有IP，但尚未实时核验接口状态和默认路由"),
                           wanSnapshotReviewSuggestions(s),s);
        if(s.defaultRouteChecked && !s.defaultRoutePresent)
            return summary(QStringLiteral("WAN_NO_DEFAULT_ROUTE"),DiagnosisSeverity::Warning,QStringLiteral("WAN已获得有效IP但没有默认路由"),
                           {QStringLiteral("检查默认路由/策略路由和拨号脚本")},s);
        return summary(QStringLiteral("WAN_NORMAL"),DiagnosisSeverity::Info,QStringLiteral("WAN 连接正常"),{},s);
    }

    if(s.cellularDialSeen&&s.pppConnected&&s.ipcpRequestCount>0&&s.ipcpAckCount==0)
        return summary(QStringLiteral("CELLULAR_PPP_IPCP_FAILED"),DiagnosisSeverity::Error,
                       QStringLiteral("WAN 建链异常：蜂窝 PPP 链路已建立，但 IPCP 地址协商未完成，尚未获得可用 WAN IP"),
                       {QStringLiteral("核对 APN/PDP 类型"),QStringLiteral("确认运营商是否分配 IP"),QStringLiteral("检查模组固件及拨号参数")},s);

    const auto layers=diagnoseWanLayers(s);
    if(layers.size()>=4){
        if(s.moduleProbeCompleted && layers[0].state==LayerState::Error && !s.moduleDetected && s.moduleName.isEmpty())
            return summary(QStringLiteral("MODULE_NOT_DETECTED"),DiagnosisSeverity::Error,QStringLiteral("模组探测完成但未获得有效AT响应"),
                           {QStringLiteral("检查 USB/模组供电"),QStringLiteral("确认驱动、AT控制口和端口占用")},s);
        if(layers[1].state==LayerState::Error)
            return summary(QStringLiteral("SIM_NOT_READY"),DiagnosisSeverity::Error,layers[1].conclusion,layers[1].suggestions,s);
        if(layers[2].state==LayerState::Error)
            return summary(QStringLiteral("REGISTRATION_FAILED"),DiagnosisSeverity::Error,layers[2].conclusion,layers[2].suggestions,s);
        if(layers[3].state==LayerState::Error)
            return summary(QStringLiteral("WAN_FAILED"),DiagnosisSeverity::Error,layers[3].conclusion,layers[3].suggestions,s);
        if(layers[3].state==LayerState::Warning){
            if(s.nvramSnapshotPresent)
                return summary(QStringLiteral("WAN_SNAPSHOT_INCONCLUSIVE"),DiagnosisSeverity::Warning,layers[3].conclusion,
                               layers[3].suggestions,s);
            return summary(QStringLiteral("WAN_IP_NOT_UPDATED"),DiagnosisSeverity::Warning,layers[3].conclusion,
                           {QStringLiteral("检查拨号/PDP 参数和状态同步")},s);
        }
    }
    return summary(QStringLiteral("UNKNOWN"),DiagnosisSeverity::Warning,QStringLiteral("未能识别具体原因"),
                   {QStringLiteral("查看报告中的最后 10 行日志"),QStringLiteral("增加 debug 日志后重新诊断")},s);
}
