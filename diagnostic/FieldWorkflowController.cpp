#include "FieldWorkflowController.h"

FieldWorkflowController::FieldWorkflowController(QObject* parent):QObject(parent)
{
    qRegisterMetaType<FieldWorkflowAction>();
    qRegisterMetaType<FieldWorkflowStep>();
}

QString FieldWorkflowController::stepText(FieldWorkflowStep step)
{
    switch(step){
    case FieldWorkflowStep::Idle:return QStringLiteral("待机");
    case FieldWorkflowStep::DiscoverDevice:return QStringLiteral("读取接口/WAN IP");
    case FieldWorkflowStep::DiagnoseWan:return QStringLiteral("分析模组/SIM/注册/WAN");
    case FieldWorkflowStep::PingMaster:return QStringLiteral("Ping主站");
    case FieldWorkflowStep::CaptureMaster:return QStringLiteral("抓取主站链路流量");
    case FieldWorkflowStep::PingTerminal:return QStringLiteral("Ping终端");
    case FieldWorkflowStep::CaptureTerminal:return QStringLiteral("抓取终端LAN流量");
    case FieldWorkflowStep::Finished:return QStringLiteral("完成");
    case FieldWorkflowStep::Cancelled:return QStringLiteral("已取消");
    case FieldWorkflowStep::Failed:return QStringLiteral("失败");
    }
    return {};
}

bool FieldWorkflowController::start(const FieldWorkflowConfig& config,QString* error)
{
    if(m_running){if(error)*error=QStringLiteral("一键现场诊断正在运行");return false;}
    if(!config.masterConfigured){if(error)*error=QStringLiteral("请先填写有效主站IP和业务端口");return false;}
    if(config.terminalTransport==TerminalTransport::Ethernet && !config.terminalConfigured){
        if(error)*error=QStringLiteral("终端选择网口通讯时必须填写有效终端IP和端口");
        return false;
    }
    m_config=config;
    m_running=true;
    moveTo(FieldWorkflowStep::DiscoverDevice,FieldWorkflowAction::DiscoverDevice);
    return true;
}

void FieldWorkflowController::moveTo(FieldWorkflowStep step,FieldWorkflowAction action)
{
    if(!m_running)return;
    m_step=step;
    emit stepChanged(step);
    emit actionRequested(action);
}

void FieldWorkflowController::cancel()
{
    if(!m_running)return;
    m_running=false;
    m_step=FieldWorkflowStep::Cancelled;
    emit stepChanged(m_step);
}

void FieldWorkflowController::operationFailed(const QString& reason)
{
    if(!m_running)return;
    m_running=false;
    m_step=FieldWorkflowStep::Failed;
    emit stepChanged(m_step);
    emit failed(reason);
}

void FieldWorkflowController::discoveryCompleted(bool wanInterfaceReady)
{
    if(!m_running || m_step!=FieldWorkflowStep::DiscoverDevice)return;
    if(!wanInterfaceReady){operationFailed(QStringLiteral("未识别到可用WAN接口，无法继续自动主站抓包"));return;}
    moveTo(FieldWorkflowStep::DiagnoseWan,FieldWorkflowAction::DiagnoseWan);
}

void FieldWorkflowController::wanDiagnosisCompleted()
{
    if(!m_running || m_step!=FieldWorkflowStep::DiagnoseWan)return;
    moveTo(FieldWorkflowStep::PingMaster,FieldWorkflowAction::PingMaster);
}

void FieldWorkflowController::masterPingCompleted()
{
    if(!m_running || m_step!=FieldWorkflowStep::PingMaster)return;
    moveTo(FieldWorkflowStep::CaptureMaster,FieldWorkflowAction::CaptureMaster);
}

void FieldWorkflowController::masterCaptureCompleted()
{
    if(!m_running || m_step!=FieldWorkflowStep::CaptureMaster)return;
    if(m_config.terminalTransport==TerminalTransport::Serial){finish();return;}
    moveTo(FieldWorkflowStep::PingTerminal,FieldWorkflowAction::PingTerminal);
}

void FieldWorkflowController::terminalPingCompleted(bool reachable)
{
    if(!m_running || m_step!=FieldWorkflowStep::PingTerminal)return;
    Q_UNUSED(reachable);
    // When network Telnet is available the master-side and terminal-side captures already ran
    // concurrently during CaptureMaster. Keep the terminal Ping evidence, then finish directly.
    if(m_config.synchronizedEthernetCapture){finish();return;}
    // ICMP may be blocked while the configured TCP service is healthy. Always capture
    // the terminal business port so the workflow can distinguish timeout/refusal/handshake states.
    moveTo(FieldWorkflowStep::CaptureTerminal,FieldWorkflowAction::CaptureTerminal);
}

void FieldWorkflowController::terminalCaptureCompleted()
{
    if(!m_running || m_step!=FieldWorkflowStep::CaptureTerminal)return;
    finish();
}

void FieldWorkflowController::finish()
{
    if(!m_running)return;
    m_running=false;
    m_step=FieldWorkflowStep::Finished;
    emit stepChanged(m_step);
    emit finished();
}
