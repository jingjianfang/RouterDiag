#pragma once
#include <QObject>
#include "ConnectivityProbe.h"
#include "DiagnosticTypes.h"
class TelnetClient;

enum class TerminalTransport { Ethernet, Serial };

struct FieldDiagnosticConfig {
    QString masterIp;
    quint16 masterPort = 2404;
    EndpointRole masterRole = EndpointRole::Client;
    TerminalTransport terminalTransport = TerminalTransport::Ethernet;
    QString terminalIp;
    quint16 terminalPort = 2404;
    EndpointRole terminalRole = EndpointRole::Server;
    int expectedConnectionSeconds = 60;
};

class FieldDiagnosticController : public QObject {
    Q_OBJECT
public:
    explicit FieldDiagnosticController(TelnetClient* control,QObject* parent=nullptr);
    void setConfig(const FieldDiagnosticConfig& config){m_config=config;}
    FieldDiagnosticConfig config() const{return m_config;}
    bool isBusy() const{return !m_pendingCommand.isEmpty();}
    void pingMaster();
    void pingTerminal();
    static QString buildMasterFilter(const FieldDiagnosticConfig& config);
    static QString buildTerminalFilter(const FieldDiagnosticConfig& config);
signals:
    void pingStarted(const QString& target);
    void pingOutputReceived(const QString& target,const QString& chunk);
    void pingFinished(const QString& target,const PingResult& result);
    void failed(const QString& reason);
private:
    void startPing(const QString& target);
    TelnetClient* m_control=nullptr;
    FieldDiagnosticConfig m_config;
    QString m_pendingCommand;
    QString m_pendingTarget;
};
