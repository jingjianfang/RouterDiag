#pragma once

#include "capture/PcapTypes.h"
#include <QList>
#include <QStringList>

enum class CaptureSide { TerminalLan, Wan };

struct DualCaptureCorrelationSummary {
    quint64 matchedPackets = 0;
    quint64 rangeMatchedPackets = 0;
    quint64 streamMatchedPackets = 0;
    quint64 terminalOnlyPackets = 0;
    quint64 wanOnlyPackets = 0;
    double averageForwardDelayMs = 0.0;
    double maximumForwardDelayMs = 0.0;
    QStringList evidence;
};

class DualCaptureCorrelator {
public:
    void reset();
    void consume(CaptureSide side,const ParsedPacket& packet);
    DualCaptureCorrelationSummary summary() const;

private:
    struct Observation {
        CaptureSide side=CaptureSide::TerminalLan;
        quint32 sequence=0;
        quint32 payloadLength=0;
        QByteArray payloadHash;
        QByteArray payload;
        QDateTime timestamp;
        QString sourceIp;
        quint16 sourcePort=0;
        QString destinationIp;
        quint16 destinationPort=0;
    };
    static bool samePayload(const Observation& a,const Observation& b);
    static bool sequenceRangeOverlap(const Observation& a,const Observation& b);
    static bool streamFragmentMatch(const Observation& a,const Observation& b);
    void trimOld(const QDateTime& now);

    QList<Observation> m_unmatched;
    quint64 m_matched=0;
    quint64 m_rangeMatched=0;
    quint64 m_streamMatched=0;
    double m_delayTotal=0.0;
    double m_delayMax=0.0;
    QStringList m_recentMatches;
};
