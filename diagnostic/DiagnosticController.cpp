#include "DiagnosticController.h"
#include "LogAnalyzer.h"
#include "DiagnosisEngine.h"
#include "telnet/TelnetClient.h"
#include "report/ReportExporter.h"
#include <QRegularExpression>

DiagnosticController::DiagnosticController(TelnetClient*c,QObject*p):QObject(p),m_client(c){
    connect(m_client,&TelnetClient::commandFinished,this,[this](const QString&cmd,const QString&out){
        if(!m_running || m_pendingCommand.isEmpty() || cmd!=m_pendingCommand) return;
        m_pendingCommand.clear();
        m_combined+=QStringLiteral("\n$ %1\n%2\n").arg(cmd,out);
        runNext();
    });
}

QStringList DiagnosticController::automaticCommands(){
    return {
        QStringLiteral("nvram get wan_ifname"),
        QStringLiteral("nvram get wan_ipaddr"),
        QStringLiteral("nvram get bkup_wan_ipaddr"),
        QStringLiteral("ifconfig 2>/dev/null || ip addr"),
        QStringLiteral("nvram get debuglog_enable"),
        QStringLiteral("nvram get syslogd_enable"),
        QStringLiteral("tail -n 500 /tmp/.systemlog 2>/dev/null || logread | tail -n 500 || tail -n 500 /var/log/messages")
    };
}

QString DiagnosticController::cleanValue(const QString&o)const{
    QStringList ls=o.split(QRegularExpression("[\\r\\n]+"),Qt::SkipEmptyParts);
    for(QString l:ls){l=l.trimmed();if(l.startsWith("nvram ")||l.endsWith("#")||l.endsWith("$")||l.endsWith(">"))continue;if(!l.contains("COMMAND TIMEOUT"))return l;}
    return{};
}

void DiagnosticController::startDiagnosis(){
    if(!m_client||!m_client->isConnected()){emit failed("Telnet control connection is not connected");return;}
    if(m_running){emit failed("WAN诊断正在执行");return;}
    if(m_client->isBusy()){emit failed("控制Telnet正在执行其他命令，请稍后再开始WAN诊断");return;}
    m_cancelled=false;m_combined.clear();m_index=0;m_commands=automaticCommands();m_pendingCommand.clear();m_running=true;
    emit progress("开始 WAN 诊断");runNext();
}
void DiagnosticController::cancel(){m_cancelled=true;}
void DiagnosticController::runNext(){
    if(m_cancelled){m_running=false;m_pendingCommand.clear();emit failed("诊断已取消");return;}
    if(m_index<m_commands.size()){
        const QString c=m_commands[m_index++];m_pendingCommand=c;emit progress(c);m_client->executeCommand(c,c.contains("systemlog")?7000:3500);return;
    }
    finish();
}
void DiagnosticController::finish(){
    m_running=false;m_pendingCommand.clear();
    WanStatus s=LogAnalyzer::analyze(m_combined);DiagnosisResult d=DiagnosisEngine::diagnose(s);emit finished(s,d,ReportExporter::buildTextReport(s,d));
}
