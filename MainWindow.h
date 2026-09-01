#pragma once

#include <QMainWindow>
#include <QVector>
#include <memory>
#include "diagnostic/DiagnosticTypes.h"
#include "diagnostic/ConnectivityProbe.h"
#include "diagnostic/ChannelAnalyzer.h"
#include "diagnostic/DualCaptureCorrelator.h"
#include "diagnostic/FieldDiagnosticController.h"
#include "diagnostic/FieldWorkflowController.h"
#include "diagnostic/DeviceDiscoveryController.h"
#include "capture/PcapTypes.h"
#include "capture/TcpStreamReassembler.h"
#include "protocol/ProtocolDiagnosis.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class TelnetClient;
class DiagnosticController;
class PacketCaptureController;
class OfflinePcapController;
class QTimer;
class QResizeEvent;
class QEvent;
class QWidget;
class QLabel;
class QPushButton;
class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QTableWidget;
class QTabWidget;
class QTreeWidget;
class DetachableTabWidget;
class DetachablePanelManager;
class CaptureSessionWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent=nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent* event) override;
    bool eventFilter(QObject* watched,QEvent* event) override;

private slots:
    void connectRouter();
    void disconnectRouter();
    void diagnose();
    void startCapture();
    void stopCapture();
    void exportPcap();
    void saveReport();
    void importSystemLog();
    void importPcap();
    void convertTcpdumpTextToPcap();
    void replayPcap();
    void stopReplay();
    void appendPacket(const ParsedPacket& packet);
    void updateStats(const CaptureStats& stats);
    void updateTerminalTransportUi();
    void updateRouterConnectionModeUi();
    void refreshSerialPorts();
    void refreshCaptureInterfaces();
    void pingMaster();
    void pingTerminal();
    void captureMaster();
    void captureTerminal();
    void showModuleLog();
    void showCommandWindow();
    void showPingWindow();
    void oneClickDiagnosis();
    void cancelOneClickDiagnosis();
    void updateCaptureModeUi();
    void showLayerDetail(int row);
    void showPacketDetail(int row);

private:
    enum class FieldCaptureMode { None, Master, TerminalEthernet };
    enum class FieldPingMode { None, Master, TerminalEthernet };

    void loginClient(TelnetClient* client,const QString& label);
    void abortRouterConnectionAttempt(const QString& reason);
    void log(const QString& text);
    void clearPacketView();
    void applyDiagnosis(const WanStatus& status,const DiagnosisResult& diagnosis,const QString& report);
    FieldDiagnosticConfig currentFieldConfig() const;
    bool prepareCaptureStorage(const QString& prefix);
    void renderFieldDiagnosis();
    FieldDiagnosisReport currentFieldReport() const;
    LayerDiagnosis currentTransportLayer() const;
    QString currentLayeredReport() const;
    void consumeProtocolPayload(const QByteArray& payload);
    void rebuildProtocolEvidenceFromStreams();
    bool startFieldCapture(FieldCaptureMode mode,const QString& iface,const QString& filter,const ChannelCriteria& criteria,bool promptForStorage=true);
    void handleWorkflowAction(FieldWorkflowAction action);
    void startWorkflowCapture(FieldCaptureMode mode);
    void updateConnectionUi();
    void loadFieldHistory();
    void saveFieldHistory();
    QList<LayerDiagnosis> currentSixLayers() const;
    QList<LayerDiagnosis> currentPresentationLayers() const;
    QString layerDetailText(const LayerDiagnosis& layer) const;
    QString packetDetailText(const ParsedPacket& packet) const;
    QString packetHexText(const ParsedPacket& packet) const;
    QString packetBusinessText(const ParsedPacket& packet) const;
    void refreshRealtimeTcpAnalysis();
    void setCaptureState(const QString& text,LayerState state=LayerState::Unknown);
    void updateCaptureActivityState(const QString& detail,LayerState state=LayerState::Normal);
    void beginPingDisplay(const QString& target);
    void appendPingDisplay(const QString& chunk);
    void finishPingDisplay(const QString& target,const PingResult& result);
    void startBackgroundModuleLog();
    void processBackgroundModuleLogText(const QString& text);
    void mergeLiveWanStatus(const WanStatus& live);
    void loadConnectionHistory();
    void saveConnectionHistory();
    bool controlCommandBusy() const;
    void displayDeviceDiscovery(const DeviceDiscoveryResult& result);
    void applyProfessionalStyle();
    void reflowResponsiveLayout(int width);
    bool routerSerialMode() const;
    bool captureTransportReady() const;
    void setupDetachableTabs();
    void setupResizableWorkspace();
    void startSynchronizedWorkflowCapture();
    void stopSynchronizedWorkflowCapture();
    void completeSynchronizedWorkflowCaptureIfReady();
    void failSynchronizedWorkflowCapture(const QString& reason);
    void consumeSynchronizedMasterPacket(const ParsedPacket& packet);
    QString autoTerminalCaptureInterface() const;
    bool validateTerminalLanSubnet(const QString& terminalIp,QString* reason=nullptr) const;
    CaptureSessionWidget* createCaptureSessionWindow(const QString& title,const QString& iface,const QString& filter,bool autoStart=false,bool autoRefreshInterfaces=true);
    void setupRc13Workspace();
    void setRouterConnectionCollapsed(bool collapsed);
    void refreshCaptureQuickFilter();
    void setCaptureTargetVisible(bool visible);
    void setupCaptureInterfaceSelector();
    void rebuildCaptureInterfaceChoices();
    QString captureInterfaceText() const;
    void setCaptureInterfaceText(const QString& iface);
    QStringList captureInterfaceChoices() const;
    void setupSerialCaptureWorkspace();
    void appendSerialConsoleText(const QString& text);
    void renderOfflineRecentPackets();
    void appendCaptureTimeline(const QString& source,const QString& detail);
    bool packetMatchesCaptureQuickFilter(const ParsedPacket& packet,const QString& search) const;
    void populateEvidenceTree(const LayerDiagnosis& layer);
    void openStatusCardDetail(QObject* card);
    void updateFieldSummary();

    Ui::MainWindow* ui;
    TelnetClient* m_control;
    TelnetClient* m_capture;
    TelnetClient* m_moduleLog;
    DiagnosticController* m_diag;
    FieldDiagnosticController* m_fieldDiag;
    FieldWorkflowController* m_workflow;
    DeviceDiscoveryController* m_discovery;
    PacketCaptureController* m_capCtrl;
    OfflinePcapController* m_offline;
    WanStatus m_lastStatus;
    DiagnosisResult m_lastDiagnosis;
    QString m_lastReport;
    QString m_discoveredWanIfname;
    QString m_discoveredWanIp;
    QString m_discoveredWanIpSource;
    QList<DeviceInterfaceInfo> m_discoveredInterfaces;
    QStringList m_actualMasterIps;
    QList<TcpSessionEvidence> m_actualMasterSessions;
    QList<ParsedPacket> m_masterDownstreamPayloads;
    quint64 m_masterUpstreamPayloadPackets=0;
    quint64 m_packetNo=0;
    bool m_offlineBulkImport=false;
    QVector<ParsedPacket> m_offlineRecentPackets;
    int m_offlineRecentWriteIndex=0;
    bool m_offlineRecentWrapped=false;
    CaptureStats m_lastCaptureStats;
    QString m_activeCaptureIface;
    QString m_activeCaptureFilter;
    ChannelAnalyzer m_packetChannelAnalyzer;
    TcpStreamReassembler m_tcpReassembler;
    QString m_liveModuleLogBuffer;
    enum class ModuleLogSetupState { Idle, CheckingDebug, SettingDebug, CommitDebug, CheckingSyslog, SettingSyslog, CommitSyslog, Tailing };
    ModuleLogSetupState m_moduleLogSetupState=ModuleLogSetupState::Idle;

    FieldCaptureMode m_fieldCaptureMode=FieldCaptureMode::None;
    FieldPingMode m_fieldPingMode=FieldPingMode::None;
    std::unique_ptr<ChannelAnalyzer> m_fieldChannelAnalyzer;
    ChannelEvidence m_masterChannelEvidence;
    ChannelEvidence m_terminalChannelEvidence;
    PingResult m_masterPing;
    PingResult m_terminalPing;
    bool m_masterPingAttempted=false;
    bool m_terminalPingAttempted=false;
    ProtocolEvidence m_protocolEvidence;
    QTimer* m_workflowCaptureTimer=nullptr;
    QTimer* m_captureNoTrafficTimer=nullptr;
    QTimer* m_serialPortRefreshTimer=nullptr;
    QTimer* m_protocolRefreshTimer=nullptr;
    bool m_controlLoggedIn=false;
    bool m_captureLoggedIn=false;
    bool m_routerDisconnectRequested=false;
    bool m_routerConnectInProgress=false;
    QString m_routerConnectionFailureMessage;
    bool m_waitingCaptureReconnectForWorkflow=false;
    QList<DetachableTabWidget*> m_detachableTabManagers;
    QList<DetachablePanelManager*> m_detachablePanelManagers;
    QTreeWidget* m_fieldEvidenceTree=nullptr;
    DetachablePanelManager* m_deviceDetailsPanelManager=nullptr;
    DetachablePanelManager* m_pingPanelManager=nullptr;
    DetachablePanelManager* m_runtimeLogPanelManager=nullptr;
    QList<CaptureSessionWidget*> m_captureSessions;
    CaptureSessionWidget* m_workflowMasterCaptureSession=nullptr;
    CaptureSessionWidget* m_workflowTerminalCaptureSession=nullptr;
    std::unique_ptr<ChannelAnalyzer> m_syncMasterAnalyzer;
    std::unique_ptr<ChannelAnalyzer> m_syncTerminalAnalyzer;
    int m_syncExpectedSessions=0;
    int m_syncStartedSessions=0;
    int m_syncStoppedSessions=0;
    bool m_syncWorkflowCaptureActive=false;
    bool m_syncCaptureSharedInterface=false;
    DualCaptureCorrelator m_dualCaptureCorrelator;
    QWidget* m_connectionCompactWidget=nullptr;
    QLabel* m_connectionCompactLabel=nullptr;
    QPushButton* m_connectionCompactToggle=nullptr;
    bool m_connectionCollapsed=false;
    QComboBox* m_captureIfaceCombo=nullptr;
    QWidget* m_captureIfacePanel=nullptr;
    QPushButton* m_refreshCaptureIfaces=nullptr;
    QPushButton* m_newCaptureWindowButton=nullptr;
    QPushButton* m_globalStopDiagnosisButton=nullptr;
    QWidget* m_fieldSummaryPanel=nullptr;
    QLabel* m_fieldSummaryStatus=nullptr;
    QLabel* m_fieldSummaryStage=nullptr;
    QLabel* m_fieldSummaryNext=nullptr;
    QPlainTextEdit* m_serialCommunicationLog=nullptr;
    QPlainTextEdit* m_serialNetworkTimeline=nullptr;
    int m_serialCommunicationTab=-1;
    int m_serialTimelineTab=-1;
    QLineEdit* m_captureQuickSearch=nullptr;
    QTreeWidget* m_evidenceTree=nullptr;
    QList<QPushButton*> m_captureQuickButtons;
    QString m_captureQuickMode=QStringLiteral("全部");
};
