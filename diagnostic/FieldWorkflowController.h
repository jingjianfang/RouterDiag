#pragma once

#include <QObject>
#include <QMetaType>
#include <QString>
#include "FieldDiagnosticController.h"

enum class FieldWorkflowStep {
    Idle,
    DiscoverDevice,
    DiagnoseWan,
    PingMaster,
    CaptureMaster,
    PingTerminal,
    CaptureTerminal,
    Finished,
    Cancelled,
    Failed
};

enum class FieldWorkflowAction {
    DiscoverDevice,
    DiagnoseWan,
    PingMaster,
    CaptureMaster,
    PingTerminal,
    CaptureTerminal
};

struct FieldWorkflowConfig {
    bool masterConfigured = false;
    TerminalTransport terminalTransport = TerminalTransport::Ethernet;
    bool terminalConfigured = false;
    bool synchronizedEthernetCapture = false;
};

class FieldWorkflowController : public QObject {
    Q_OBJECT
public:
    explicit FieldWorkflowController(QObject* parent=nullptr);

    bool start(const FieldWorkflowConfig& config,QString* error=nullptr);
    void cancel();
    void operationFailed(const QString& reason);

    void discoveryCompleted(bool wanInterfaceReady);
    void wanDiagnosisCompleted();
    void masterPingCompleted();
    void masterCaptureCompleted();
    void terminalPingCompleted(bool reachable);
    void terminalCaptureCompleted();

    bool isRunning() const{return m_running;}
    FieldWorkflowStep step() const{return m_step;}
    static QString stepText(FieldWorkflowStep step);

signals:
    void actionRequested(FieldWorkflowAction action);
    void stepChanged(FieldWorkflowStep step);
    void finished();
    void failed(const QString& reason);

private:
    void moveTo(FieldWorkflowStep step,FieldWorkflowAction action);
    void finish();

    FieldWorkflowConfig m_config;
    FieldWorkflowStep m_step=FieldWorkflowStep::Idle;
    bool m_running=false;
};

Q_DECLARE_METATYPE(FieldWorkflowAction)
Q_DECLARE_METATYPE(FieldWorkflowStep)
