#pragma once
#include "PcapTypes.h"
#include <QHash>
#include <QSet>
#include <QQueue>
class PacketAnalyzer {
public:
    void consume(const ParsedPacket& packet);
    CaptureStats stats() const { return m_stats; }
    QStringList topConversations(int limit=10) const;
    void reset();
private:
    QString flowKey(const ParsedPacket& p) const;
    QString conversationKey(const ParsedPacket& p) const;
    CaptureStats m_stats;
    QHash<QString,quint64> m_conversations;
    QSet<QString> m_tcpSequenceSeen;
    QQueue<QString> m_tcpSequenceOrder;
    QSet<QString> m_pendingSyn;
};
