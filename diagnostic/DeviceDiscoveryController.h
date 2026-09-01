#pragma once

#include <QObject>
#include <QList>
#include <QString>
#include <QStringList>

class TelnetClient;

struct DeviceInterfaceInfo {
    QString name;
    QString ipv4;
    QString netmask;
    bool up = false;
};

struct DeviceDiscoveryResult {
    QString wanIfname;
    QString wanIp;
    QString wanIpSource;
    QString wanNvramIp;
    QString backupWanIp;
    QString commWanIp;
    QList<DeviceInterfaceInfo> interfaces;
    bool wanInterfaceStateKnown = false;
    bool wanInterfaceUp = false;
    bool defaultRouteChecked = false;
    bool defaultRoutePresent = false;
    QString defaultGateway;
    QString defaultRouteInterface;

    QString moduleControlDevice;
    QString moduleManufacturer;
    QString moduleModel;
    QString moduleFirmware;
    bool moduleAtResponsive = false;
    bool moduleProbeAttempted = false;
    bool moduleProbeCompleted = false;

    QString simStatus;
    QString cpinRaw;
    QString cereg;
    QString cgreg;
    QString creg;
    QString c5greg;
    int cgatt = -1;
    int csq = -1;
    int rsrp = 999;
    int sinr = 999;
    bool usingBackupCard = false;
    QString nvramNetwork;
    QString nvramFirmware;
    int commModuleStatus = -1;
    int commDialStatus = -1;
    int wanUp = -1;
    int backupWanUp = -1;
    QString operatorName;
    int operatorAccessTechnology = -1;
    QStringList atErrors;
};

class DeviceDiscoveryParser {
public:
    static QList<DeviceInterfaceInfo> parseInterfaces(const QString& output);
    static DeviceDiscoveryResult buildResult(const QString& wanIfnameOutput,
                                             const QString& wanIpOutput,
                                             const QString& backupWanIpOutput,
                                             const QString& ifconfigOutput,
                                             const QString& routeOutput=QString(),
                                             const QString& backupWanIfnameOutput=QString(),
                                             const QString& wanIfname2Output=QString(),
                                             const QString& commWanIpOutput=QString(),
                                             bool backupActive=false);
    static QStringList parseModuleDevices(const QString& output);
    static bool atResponseOk(const QString& output);
    static QString parseAtValue(const QString& output,const QString& command);
    static QString parseAtTaggedValue(const QString& output,const QString& prefix);
    static QString parseAtiManufacturer(const QString& output);
    static QString parseAtiModel(const QString& output);
    static QString parseAtiFirmware(const QString& output);
};

class DeviceDiscoveryController : public QObject {
    Q_OBJECT
public:
    explicit DeviceDiscoveryController(TelnetClient* client,QObject* parent=nullptr);
    bool isRunning() const{return m_running;}
    void start();

signals:
    void progress(const QString& message);
    void finished(const DeviceDiscoveryResult& result);
    void failed(const QString& reason);

private:
    enum class Phase { BaseDiscovery, ProbeAti, QueryModuleInfo };

    void runNext();
    void handleCommandResult(const QString& command,const QString& output);
    void startModuleProbe();
    void finish();
    static QString cleanScalar(const QString& output);
    static QString buildAtCommand(const QString& device,const QString& atCommand);
    static QString buildFastNvramCommand();
    static QString fastNvramValue(const QString& output,const QString& key);

    TelnetClient* m_client=nullptr;
    QStringList m_commands;
    int m_index=0;
    QString m_pendingCommand;
    QString m_fastNvramOutput;
    QString m_wanIfnameOutput;
    QString m_backupWanIfnameOutput;
    QString m_wanIfname2Output;
    QString m_wanIpOutput;
    QString m_backupWanIpOutput;
    QString m_commWanIpOutput;
    QString m_ifconfigOutput;
    QString m_routeOutput;
    QString m_moduleHintOutput;
    QString m_moduleDeviceOutput;
    QString m_moduleNvramDeviceOutput;
    QString m_nvramCurrentModuleName;
    QString m_nvramSubmoduleName;
    QString m_nvramCommName;
    QString m_nvramBackupModuleName;
    QString m_nvramNetwork;
    QString m_nvramSimStatus;
    QString m_nvramFirmware;
    int m_nvramCommModuleStatus=-1;
    int m_nvramCommDialStatus=-1;
    int m_nvramWanUp=-1;
    int m_nvramBackupWanUp=-1;
    int m_nvramRsrp=999;
    int m_nvramSinr=999;
    bool m_usingBackupCard=false;
    QStringList m_moduleCandidates;
    int m_moduleCandidateIndex=0;
    QString m_activeModuleDevice;
    QString m_activeAtCommand;
    int m_moduleInfoIndex=0;
    QString m_moduleManufacturer;
    QString m_moduleModel;
    QString m_moduleFirmware;
    QString m_simStatus;
    QString m_cpinRaw;
    QString m_cereg;
    QString m_cgreg;
    QString m_creg;
    QString m_c5greg;
    int m_cgatt=-1;
    int m_csq=-1;
    QString m_operatorName;
    int m_operatorAccessTechnology=-1;
    QStringList m_atErrors;
    bool m_moduleAtResponsive=false;
    bool m_moduleProbeAttempted=false;
    bool m_running=false;
    Phase m_phase=Phase::BaseDiscovery;
};
