#pragma once
#include <QString>
#include <QStringList>
#include <QMetaType>

enum class PingFailureKind {
    None,
    NoEchoReply,
    NetworkUnreachable,
    DestinationHostUnreachable,
    AddressResolutionFailed
};

struct PingResult {
    bool validOutput = false;
    bool reachable = false;
    int transmitted = -1;
    int received = -1;
    int packetLossPercent = -1;
    double minRttMs = -1.0;
    double avgRttMs = -1.0;
    double maxRttMs = -1.0;
    PingFailureKind failureKind = PingFailureKind::None;
    QString failureReason;
    QString rawOutput;
    QStringList evidence;
};
Q_DECLARE_METATYPE(PingResult)

class ConnectivityProbe {
public:
    static bool isValidIpv4(const QString& ip);
    static bool isUsableWanIpv4(const QString& ip);
    static bool isUsableWanInterfaceName(const QString& name);
    static bool sameIpv4Subnet(const QString& firstIp,const QString& secondIp,const QString& netmask);
    static QString buildPingCommand(const QString& ip, int count = 3);
    static PingResult parsePingOutput(const QString& output);
};
