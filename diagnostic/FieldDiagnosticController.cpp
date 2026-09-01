#include "FieldDiagnosticController.h"
#include "telnet/TelnetClient.h"

FieldDiagnosticController::FieldDiagnosticController(TelnetClient* control,QObject* parent)
    :QObject(parent),m_control(control){
    if(m_control){
        connect(m_control,&TelnetClient::visibleTextReceived,this,[this](const QString& chunk){
            if(!m_pendingCommand.isEmpty() && m_pendingCommand.startsWith(QStringLiteral("ping -c ")))
                emit pingOutputReceived(m_pendingTarget,chunk);
        });
        connect(m_control,&TelnetClient::commandFinished,this,[this](const QString& command,const QString& output){
            if(command!=m_pendingCommand || m_pendingCommand.isEmpty()) return;
            const QString target=m_pendingTarget;
            m_pendingCommand.clear();m_pendingTarget.clear();
            emit pingFinished(target,ConnectivityProbe::parsePingOutput(output));
        });
    }
}

QString FieldDiagnosticController::buildMasterFilter(const FieldDiagnosticConfig& c){
    if(!ConnectivityProbe::isValidIpv4(c.masterIp) || c.masterPort==0) return {};
    // The configured master IP is an expected/reference address. A client master may arrive
    // through NAT, a cluster or a backup egress address, so never restrict business TCP to it.
    return QStringLiteral("((host %1 and icmp) or tcp port %2)").arg(c.masterIp).arg(c.masterPort);
}

QString FieldDiagnosticController::buildTerminalFilter(const FieldDiagnosticConfig& c){
    if(c.terminalTransport!=TerminalTransport::Ethernet || !ConnectivityProbe::isValidIpv4(c.terminalIp) || c.terminalPort==0) return {};
    return QStringLiteral("host %1 and (icmp or tcp port %2)").arg(c.terminalIp).arg(c.terminalPort);
}

void FieldDiagnosticController::startPing(const QString& target){
    if(!m_control || !m_control->isConnected()){emit failed(QStringLiteral("Telnet控制连接未建立"));return;}
    if(!m_pendingCommand.isEmpty()){emit failed(QStringLiteral("已有Ping诊断正在执行"));return;}
    if(m_control->isBusy()){emit failed(QStringLiteral("控制Telnet正在执行其他命令，请等待当前任务完成后再Ping"));return;}
    const QString command=ConnectivityProbe::buildPingCommand(target,4);
    if(command.isEmpty()){emit failed(QStringLiteral("无效IPv4地址: %1").arg(target));return;}
    m_pendingCommand=command;m_pendingTarget=target;
    emit pingStarted(target);
    m_control->executeCommand(command,9000);
}

void FieldDiagnosticController::pingMaster(){
    startPing(m_config.masterIp);
}

void FieldDiagnosticController::pingTerminal(){
    if(m_config.terminalTransport!=TerminalTransport::Ethernet){
        emit failed(QStringLiteral("串口模式不执行终端IP Ping，也不使用/dev/ttyUSB*作为终端串口"));
        return;
    }
    startPing(m_config.terminalIp);
}
