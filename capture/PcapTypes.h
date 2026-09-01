#pragma once
#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QStringList>
#include <QtGlobal>
#include <QMetaType>

namespace PcapLinkType {
constexpr quint32 Null = 0;
constexpr quint32 Ethernet = 1;
constexpr quint32 Raw = 101;
constexpr quint32 LinuxSll = 113;
constexpr quint32 LinuxSll2 = 276;
}

struct PcapGlobalHeaderInfo {
    bool valid = false;
    bool littleEndian = true;
    bool nanosecondResolution = false;
    quint16 versionMajor = 0;
    quint16 versionMinor = 0;
    quint32 snapLen = 0;
    quint32 linkType = 0;
};

struct PcapRecord {
    quint32 tsSec = 0;
    quint32 tsFraction = 0;
    quint32 includedLength = 0;
    quint32 originalLength = 0;
    bool nanosecondResolution = false;
    QByteArray data;
};

struct ParsedPacket {
    bool valid = false;
    QString error;
    QDateTime timestamp;
    QString sourceIp;
    QString destinationIp;
    QString protocol;
    quint16 sourcePort = 0;
    quint16 destinationPort = 0;
    quint8 tcpFlags = 0;
    quint32 sequence = 0;
    quint32 acknowledgement = 0;
    quint32 capturedLength = 0;
    quint16 ipTotalLength = 0;
    quint8 tcpHeaderLength = 0;
    quint32 tcpPayloadLength = 0;
    QByteArray payload;
    quint8 icmpType = 255;
    QString summary;
};

struct CaptureStats {
    quint64 totalPackets = 0;
    quint64 totalBytes = 0;
    quint64 tcpPackets = 0;
    quint64 udpPackets = 0;
    quint64 icmpPackets = 0;
    quint64 tcpSyn = 0;
    quint64 tcpRst = 0;
    quint64 tcpFin = 0;
    quint64 suspectedRetransmissions = 0;
    quint64 icmpEchoRequests = 0;
    quint64 icmpEchoReplies = 0;
    quint64 synWithoutResponse = 0;
};

Q_DECLARE_METATYPE(PcapGlobalHeaderInfo)
Q_DECLARE_METATYPE(PcapRecord)
Q_DECLARE_METATYPE(ParsedPacket)
Q_DECLARE_METATYPE(CaptureStats)
