#include "ReportExporter.h"
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace {
QString stateText(LayerState state)
{
    switch(state){
    case LayerState::Normal:return QStringLiteral("正常");
    case LayerState::Warning:return QStringLiteral("关注");
    case LayerState::Error:return QStringLiteral("异常");
    case LayerState::NotTested:return QStringLiteral("未测试");
    default:return QStringLiteral("未知");
    }
}

int stateRank(LayerState state)
{
    switch(state){
    case LayerState::Error:return 4;
    case LayerState::Warning:return 3;
    case LayerState::Normal:return 2;
    case LayerState::Unknown:return 1;
    case LayerState::NotTested:return 0;
    }
    return 0;
}

QString confidenceText(Confidence confidence)
{
    switch(confidence){
    case Confidence::High:return QStringLiteral("高");
    case Confidence::Medium:return QStringLiteral("中");
    default:return QStringLiteral("低");
    }
}

const LayerDiagnosis* findLayer(const QList<LayerDiagnosis>& layers,const QString& name)
{
    for(const LayerDiagnosis& d:layers)
        if(d.layer==name) return &d;
    return nullptr;
}

LayerDiagnosis missingLayer(const QString& name,const QString& conclusion)
{
    LayerDiagnosis d;
    d.layer=name;
    d.state=LayerState::NotTested;
    d.confidence=Confidence::Low;
    d.conclusion=conclusion;
    return d;
}

void appendLayer(QString& out,const QString& title,const LayerDiagnosis& d)
{
    out+=title+QStringLiteral("\n");
    out+=QStringLiteral("状态: %1 | 置信度: %2\n").arg(stateText(d.state),confidenceText(d.confidence));
    out+=QStringLiteral("结论: %1\n").arg(d.conclusion.isEmpty()?QStringLiteral("无明确结论"):d.conclusion);
    if(!d.evidence.isEmpty()){
        out+=QStringLiteral("证据:\n");
        for(const QString& e:d.evidence) out+=QStringLiteral("  - %1\n").arg(e);
    }
    if(!d.suggestions.isEmpty()){
        out+=QStringLiteral("建议:\n");
        for(const QString& s:d.suggestions) out+=QStringLiteral("  - %1\n").arg(s);
    }
    out+=QStringLiteral("\n");
}
}

QString ReportExporter::buildTextReport(const WanStatus&s,const DiagnosisResult&d)
{
    QString x="============================================================\n四信路由器通信诊断工具 - WAN 连接诊断报告\n============================================================\n";
    if(s.nvramSnapshotPresent){
        x+=QStringLiteral("[i] 数据源: NVRAM配置快照 (%1, %2项)\n").arg(s.nvramSnapshotFormat).arg(s.nvramRecordCount);
        x+=QStringLiteral("[i] WAN快照: active=%1 source=%2 main=%3/up%4 backup=%5/up%6\n")
            .arg(s.activeWanPath.isEmpty()?QStringLiteral("unknown"):s.activeWanPath,
                 s.wanIpSource.isEmpty()?QStringLiteral("未确认"):s.wanIpSource,
                 s.wanProto.isEmpty()?QStringLiteral("未知"):s.wanProto)
            .arg(s.wanUp)
            .arg(s.backupWanProto.isEmpty()?QStringLiteral("未知"):s.backupWanProto)
            .arg(s.backupWanUp);
        if(s.moduleIdentityMismatch)
            x+=QStringLiteral("[i] 模组标识提示: 配置=%1 / 运行=%2（不直接判故障）\n").arg(s.configuredModuleName,s.runtimeModuleName);
        if(s.dtsEnabled>=0 || s.dtsRun>=0 || s.dtsConStatus>=0 || s.dtsDcuConStatus>=0 || s.dtsDcuConStatus2>=0)
            x+=QStringLiteral("[i] DTS快照: enable=%1 run=%2 p1=%3/%4 p2=%5/%6 active=%7\n")
                .arg(s.dtsEnabled).arg(s.dtsRun).arg(s.dtsConStatus).arg(s.dtsDcuConStatus)
                .arg(s.dtsConStatus2).arg(s.dtsDcuConStatus2).arg(s.dtsActiveProfile);
    }
    x+=QStringLiteral("[+] 模组型号: %1\n").arg(s.moduleName.isEmpty()?"未知":s.moduleName);
    x+=QStringLiteral("[+] SIM 卡状态: %1\n").arg(s.simStatus.isEmpty()?"未知":s.simStatus);
    x+=QStringLiteral("[+] 网络注册: %1 / 5G:%2\n").arg(s.cgreg.isEmpty()?"未知":s.cgreg,s.c5greg.isEmpty()?"未知":s.c5greg);
    x+=QStringLiteral("[+] 数据附着: %1\n").arg(s.cgatt<0?"未知":QString::number(s.cgatt));
    x+=QStringLiteral("[+] 信号: CSQ=%1 RSRP=%2\n").arg(s.csq).arg(s.rsrp==999?0:s.rsrp);
    x+=QStringLiteral("[+] 运营商: %1 | 接入制式AcT=%2\n").arg(s.operatorName.isEmpty()?QStringLiteral("未知"):s.operatorName).arg(s.operatorAccessTechnology);
    x+=QStringLiteral("[+] 当前WAN状态: linkDown=%1 DHCP失败=%2 PPPoE失败=%3 WAN失败=%4\n")
        .arg(s.physicalLinkDown).arg(s.dhcpFailure).arg(s.pppoeFailure).arg(s.wanNetworkFailed);
    x+=QStringLiteral("[+] 本次历史事件: linkDown=%1 DHCP失败=%2 PPPoE失败=%3 WAN失败=%4 NetworkUnreachable=%5\n")
        .arg(s.physicalLinkDownCount).arg(s.dhcpFailureCount).arg(s.pppoeFailureCount).arg(s.wanNetworkFailedCount).arg(s.networkUnreachableCount);
    x+=QStringLiteral("[+] 当前 IP: %1\n[!] 结论: %2\n").arg(s.wanIp,d.conclusion);
    if(!d.suggestions.isEmpty()){
        x+="建议:\n";
        for(int i=0;i<d.suggestions.size();++i)x+=QStringLiteral("%1. %2\n").arg(i+1).arg(d.suggestions[i]);
    }
    x+="============================================================\n";
    return x;
}

QString ReportExporter::buildFieldReport(const WanStatus& wan,const FieldDiagnosisReport& field,const ProtocolEvidence& protocol)
{
    QString out;
    out+=QStringLiteral("============================================================\n");
    out+=QStringLiteral("四信路由器通信诊断工具 - 现场四层综合诊断报告\n");
    out+=QStringLiteral("============================================================\n");
    if(!field.overallConclusion.isEmpty())
        out+=QStringLiteral("综合结论: %1\n\n").arg(field.overallConclusion);
    out+=QStringLiteral("现场状态: 模组=%1 | SIM=%2 | 运营商=%3 | WAN接口=%4 | WAN IP=%5\n")
        .arg(wan.moduleName.isEmpty()?QStringLiteral("未知"):wan.moduleName,
             wan.simStatus.isEmpty()?QStringLiteral("未知"):wan.simStatus,
             wan.operatorName.isEmpty()?QStringLiteral("未知"):wan.operatorName,
             wan.wanIfname.isEmpty()?QStringLiteral("未知"):wan.wanIfname,
             wan.wanIp);
    if(wan.nvramSnapshotPresent){
        out+=QStringLiteral("配置快照: %1 / %2项 | 活动WAN提示=%3 | IP来源=%4\n")
            .arg(wan.nvramSnapshotFormat).arg(wan.nvramRecordCount)
            .arg(wan.activeWanPath.isEmpty()?QStringLiteral("unknown"):wan.activeWanPath,
                 wan.wanIpSource.isEmpty()?QStringLiteral("未确认"):wan.wanIpSource);
    }
    out+=QStringLiteral("WAN历史事件: linkDown=%1 DHCP失败=%2 PPPoE失败=%3 WAN失败=%4 NetworkUnreachable=%5\n\n")
        .arg(wan.physicalLinkDownCount).arg(wan.dhcpFailureCount).arg(wan.pppoeFailureCount)
        .arg(wan.wanNetworkFailedCount).arg(wan.networkUnreachableCount);

    const LayerDiagnosis missingModule=missingLayer(QStringLiteral("CELLULAR_MODULE"),QStringLiteral("模组/AT尚未测试"));
    const LayerDiagnosis missingSim=missingLayer(QStringLiteral("SIM"),QStringLiteral("SIM卡尚未测试"));
    const LayerDiagnosis missingReg=missingLayer(QStringLiteral("REGISTRATION"),QStringLiteral("网络注册尚未测试"));
    const LayerDiagnosis missingWan=missingLayer(QStringLiteral("WAN"),QStringLiteral("WAN/IP尚未测试"));
    const LayerDiagnosis missingTransport=missingLayer(QStringLiteral("TRANSPORT"),QStringLiteral("主站与终端链路尚未测试"));
    const LayerDiagnosis missingBusiness=missingLayer(QStringLiteral("BUSINESS_DATA"),QStringLiteral("业务数据尚未测试"));

    const LayerDiagnosis& module=findLayer(field.layers,"CELLULAR_MODULE")?*findLayer(field.layers,"CELLULAR_MODULE"):missingModule;
    const LayerDiagnosis& sim=findLayer(field.layers,"SIM")?*findLayer(field.layers,"SIM"):missingSim;
    const LayerDiagnosis& reg=findLayer(field.layers,"REGISTRATION")?*findLayer(field.layers,"REGISTRATION"):missingReg;
    const LayerDiagnosis& wanLayer=findLayer(field.layers,"WAN")?*findLayer(field.layers,"WAN"):missingWan;
    const LayerDiagnosis& transport=findLayer(field.layers,"TRANSPORT")?*findLayer(field.layers,"TRANSPORT"):missingTransport;
    const LayerDiagnosis& business=findLayer(protocol.layers,"BUSINESS_DATA")?*findLayer(protocol.layers,"BUSINESS_DATA"):missingBusiness;

    LayerDiagnosis access;
    access.layer=QStringLiteral("ACCESS");
    access.state=LayerState::NotTested;access.confidence=Confidence::Low;
    const QList<QPair<QString,const LayerDiagnosis*>> children={{QStringLiteral("模组"),&module},{QStringLiteral("SIM"),&sim},{QStringLiteral("网络注册"),&reg}};
    int worst=-1;
    QStringList conclusions;
    for(const auto& child:children){
        const LayerDiagnosis& d=*child.second;
        conclusions<<QStringLiteral("%1：%2").arg(child.first,d.conclusion);
        if(stateRank(d.state)>worst){worst=stateRank(d.state);access.state=d.state;access.confidence=d.confidence;}
        access.evidence<<QStringLiteral("【%1】状态=%2，置信度=%3").arg(child.first,stateText(d.state),confidenceText(d.confidence));
        for(const QString& ev:d.evidence)access.evidence<<QStringLiteral("%1 - %2").arg(child.first,ev);
        for(const QString& tip:d.suggestions)access.suggestions<<QStringLiteral("%1 - %2").arg(child.first,tip);
    }
    access.conclusion=conclusions.join(QStringLiteral("；"));

    appendLayer(out,QStringLiteral("[1] 模组 / SIM / 网络注册"),access);
    appendLayer(out,QStringLiteral("[2] WAN/IP"),wanLayer);
    appendLayer(out,QStringLiteral("[3] 主站与终端链路"),transport);
    appendLayer(out,QStringLiteral("[4] 业务数据"),business);
    out+=QStringLiteral("说明: 内部仍独立保留模组、SIM、网络注册诊断；界面和报告将它们汇总为第1大层。业务数据层统一分析普通IEC101/104与国网加密101/104。\n");
    out+=QStringLiteral("============================================================\n");
    return out;
}

bool ReportExporter::saveTextReport(const QString&p,const WanStatus&s,const DiagnosisResult&d,QString*e)
{
    QFile f(p);
    if(!f.open(QIODevice::WriteOnly|QIODevice::Text)){if(e)*e=f.errorString();return false;}
    f.write(buildTextReport(s,d).toUtf8());
    return true;
}

bool ReportExporter::saveJsonReport(const QString&p,const WanStatus&s,const DiagnosisResult&d,QString*e)
{
    QJsonObject o{{"wan_ifname",s.wanIfname},{"wan_ip",s.wanIp},{"module",s.moduleName},{"sim",s.simStatus},{"cgreg",s.cgreg},{"c5greg",s.c5greg},{"cgatt",s.cgatt},{"csq",s.csq},{"operator",s.operatorName},{"operator_act",s.operatorAccessTechnology},{"rsrp",s.rsrp},{"apn",s.apn},{"link_down_events",s.physicalLinkDownCount},{"dhcp_failure_events",s.dhcpFailureCount},{"pppoe_failure_events",s.pppoeFailureCount},{"wan_failure_events",s.wanNetworkFailedCount},{"network_unreachable_events",s.networkUnreachableCount},{"diagnosis_type",d.type},{"conclusion",d.conclusion}};
    if(s.nvramSnapshotPresent){
        o["nvram_snapshot_format"]=s.nvramSnapshotFormat;
        o["nvram_record_count"]=s.nvramRecordCount;
        o["active_wan_path_hint"]=s.activeWanPath;
        o["wan_ip_source"]=s.wanIpSource;
        o["module_identity_mismatch"]=s.moduleIdentityMismatch;
    }
    QJsonArray a;for(auto&v:d.suggestions)a.append(v);o["suggestions"]=a;
    QFile f(p);if(!f.open(QIODevice::WriteOnly)){if(e)*e=f.errorString();return false;}
    f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));return true;
}
