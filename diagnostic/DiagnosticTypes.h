#pragma once
#include <QString>
#include <QStringList>
#include <QList>

struct CmeErrorRecord {
    QString command;
    int code = -1;
    QString raw;
};

enum class LayerState { Unknown, NotTested, Normal, Warning, Error };
enum class Confidence { Low, Medium, High };
enum class EndpointRole { Client, Server };

struct LayerDiagnosis {
    QString layer;
    LayerState state = LayerState::Unknown;
    Confidence confidence = Confidence::Low;
    QString conclusion;
    QStringList evidence;
    QStringList suggestions;
};

struct FieldDiagnosisReport {
    QList<LayerDiagnosis> layers;
    QString overallConclusion;
};

struct WanStatus {
    QString wanIfname;
    QString wanIp = QStringLiteral("0.0.0.0");
    QString backupWanIp = QStringLiteral("0.0.0.0");
    bool nvramSnapshotPresent = false;
    QString nvramSnapshotFormat;
    int nvramRecordCount = 0;
    QString wanIpSource;
    QString activeWanPath; // primary / backup / unknown; snapshot hint only, live interface/route wins
    QString wanTopology; // primary-only / backup-only / dual / unknown
    bool primaryWanPresent = false;
    bool backupWanPresent = false;
    QString wanProto;
    QString backupWanProto;
    QString nvramPrimaryWanIp;
    QString commWanIp;
    int wanUp = -1;
    int backupWanUp = -1;
    int commDialStatus = -1;
    bool wanIpFromNvramSnapshot = false;
    QString moduleName;
    QString configuredModuleName;
    QString runtimeModuleName;
    bool moduleIdentityMismatch = false;
    int commModuleStatus = -1;
    QString radioAccessMode;
    QString moduleCode;
    QString firmware;
    QString moduleControlDevice;
    bool moduleAtResponsive = false;
    bool moduleDetected = false;
    bool moduleProbeAttempted = false;
    bool moduleProbeCompleted = false;

    QString simStatus;
    QString cpinRaw;
    QString simCardRaw;
    bool simStatusFromNvram = false;
    int cpinErrorCount = 0;

    QString cereg;
    QString cgreg;
    QString c5greg;
    QString creg;
    QString mcc;
    QString mnc;
    QString lac;
    QString cellId;
    int pci = -1;
    QString band;
    int earfcn = -1;
    int rssi = 999;
    int cgatt = -1;
    int csq = -1;
    QString operatorName;
    int operatorMode = -1;
    int operatorFormat = -1;
    int operatorAccessTechnology = -1;
    int rsrp = 999;
    int rsrq = 999;
    int sinr = 999;
    QString apn;
    int dialFinish = -1;

    bool pppConnected = false;
    bool cellularDialSeen = false;
    int lcpRequestCount = 0;
    int lcpAckCount = 0;
    int ipcpRequestCount = 0;
    int ipcpAckCount = 0;
    int ipcpNakCount = 0;
    int wanNotUpCount = 0;
    bool physicalLinkDown = false;
    bool dhcpFailure = false;
    bool pppoeFailure = false;
    bool wanNetworkFailed = false;
    bool wanInterfaceStateKnown = false;
    bool wanInterfaceUp = false;
    bool defaultRouteChecked = false;
    bool defaultRoutePresent = false;
    QString defaultGateway;
    QString defaultRouteInterface;
    int physicalLinkDownCount = 0;
    int dhcpFailureCount = 0;
    int pppoeFailureCount = 0;
    int wanNetworkFailedCount = 0;
    int networkUnreachableCount = 0;

    int dcucom = -1;
    int dtsEnabled = -1;
    int dtsRun = -1;
    int dtsConStatus = -1;
    int dtsDcuConStatus = -1;
    int dtsConStatus2 = -1;
    int dtsDcuConStatus2 = -1;
    int dtsActiveProfile = -1;
    QString dcuIp;
    int dcuPort = -1;
    int serialBaudrate = -1;
    int serialDatabit = -1;
    int serialStopbit = -1;
    int serialParity = -1;
    int serialFlowcontrol = -1;
    bool dtsStarted = false;
    bool southTcpConfigured = false;
    bool southTcpConnected = false;
    QString observedTerminalTransport;

    QList<CmeErrorRecord> cmeErrors;
    QStringList evidence;
    QStringList tailLines;
};

enum class DiagnosisSeverity { Info, Warning, Error };

struct DiagnosisResult {
    QString type;
    DiagnosisSeverity severity = DiagnosisSeverity::Info;
    QString conclusion;
    QStringList suggestions;
    QStringList evidence;
};
