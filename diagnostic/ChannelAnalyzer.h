#pragma once
#include "capture/PcapTypes.h"
#include "diagnostic/ConnectivityProbe.h"
#include "diagnostic/DiagnosticTypes.h"
#include <QHash>
#include <QList>

struct ChannelCriteria {
    QString peerIp;
    quint16 peerPort = 0;
    bool requirePeerPort = false;
};

struct TcpSessionEvidence {
    QString initiatorIp;
    quint16 initiatorPort = 0;
    QString responderIp;
    quint16 responderPort = 0;
    bool initiatorKnown = false;
    quint64 synCount = 0;
    quint64 synAckCount = 0;
    quint64 ackFromInitiator = 0;
    quint64 payloadPacketsFromInitiator = 0;
    quint64 payloadPacketsFromResponder = 0;
    quint64 payloadBytesFromInitiator = 0;
    quint64 payloadBytesFromResponder = 0;
    quint64 rstFromInitiator = 0;
    quint64 rstFromResponder = 0;
    quint64 finFromInitiator = 0;
    quint64 finFromResponder = 0;
    QString firstRstIp;
    quint16 firstRstPort = 0;
    QString firstFinIp;
    quint16 firstFinPort = 0;
    bool handshakeComplete = false;
    QDateTime firstSeen;
    QDateTime lastSeen;
    QDateTime firstPayloadTime;
    QDateTime lastPayloadTime;
    QDateTime firstRstTime;
    QDateTime firstFinTime;
};

struct ChannelEvidence {
    quint64 packets = 0;
    quint64 syn = 0;
    quint64 synAck = 0;
    quint64 ack = 0;
    quint64 pshAck = 0;
    quint64 rst = 0;
    quint64 fin = 0;
    quint64 payloadPackets = 0;
    quint64 payloadBytes = 0;
    quint64 icmp140 = 0;
    quint64 icmp140FromPeer = 0;
    quint64 synFromPeer = 0;
    quint64 synToPeer = 0;
    bool handshakeComplete = false;
    QList<TcpSessionEvidence> tcpSessions;
};

class ChannelAnalyzer {
public:
    explicit ChannelAnalyzer(ChannelCriteria criteria = {});
    void consume(const ParsedPacket& packet);
    ChannelEvidence evidence() const { return m_evidence; }
    void reset();

    static LayerDiagnosis diagnoseMaster(const PingResult& ping,const ChannelEvidence& evidence);
    static LayerDiagnosis diagnoseMaster(const PingResult& ping,const ChannelEvidence& evidence,EndpointRole role,int expectedSeconds);
    static LayerDiagnosis diagnoseTerminalEthernet(const PingResult& ping,const ChannelEvidence& evidence);
    static LayerDiagnosis diagnoseTerminalEthernet(const PingResult& ping,const ChannelEvidence& evidence,EndpointRole role,int expectedSeconds);
    static QList<TcpSessionEvidence> actualPeerSessions(const ChannelEvidence& evidence,EndpointRole role,quint16 businessPort);
    static QStringList actualPeerIps(const ChannelEvidence& evidence,EndpointRole role,quint16 businessPort);
    static bool packetFromActualPeer(const ParsedPacket& packet,const QList<TcpSessionEvidence>& sessions,EndpointRole role,quint16 businessPort);
    static bool packetFromActualPeer(const ParsedPacket& packet,const QStringList& actualPeerIps,EndpointRole role,quint16 businessPort);
    static QString tcpSessionReport(const ChannelEvidence& evidence,const QString& title=QString());

private:
    bool matches(const ParsedPacket& p) const;
    static QString endpoint(const QString& ip,quint16 port);
    static QString normalizedFlowKey(const ParsedPacket& p);
    void refreshSessions();

    ChannelCriteria m_criteria;
    ChannelEvidence m_evidence;
    QHash<QString,TcpSessionEvidence> m_sessions;
};
