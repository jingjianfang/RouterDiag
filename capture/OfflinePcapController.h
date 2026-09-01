#pragma once

#include <QObject>
#include <QList>
#include <QTimer>
#include "PcapTypes.h"
#include "PacketAnalyzer.h"

class OfflinePcapController : public QObject {
    Q_OBJECT
public:
    enum class ReplaySpeed { X1, X5, X10, Fastest };
    Q_ENUM(ReplaySpeed)

    explicit OfflinePcapController(QObject* parent=nullptr);

    bool loadFile(const QString& path, QString* error=nullptr);
    bool loadData(const QByteArray& data, QString* error=nullptr, const QString& sourceName=QString());
    void analyzeAll();
    void startReplay(ReplaySpeed speed);
    void stopReplay();
    void clear();

    int packetCount() const { return m_totalPacketCount; }
    PcapGlobalHeaderInfo globalHeader() const { return m_header; }
    CaptureStats stats() const { return m_analyzer.stats(); }
    QString sourceName() const { return m_sourceName; }
    bool isLoaded() const { return m_header.valid; }
    bool isReplaying() const { return m_replaying; }
    bool replayAvailable() const { return m_replayAvailable; }

signals:
    void loaded(const QString& sourceName, int packetCount, const PcapGlobalHeaderInfo& header);
    void loadProgress(qint64 bytesRead, qint64 totalBytes, int packetCount);
    void packetReady(const ParsedPacket& packet);
    void statsUpdated(const CaptureStats& stats);
    void replayStarted();
    void replayFinished();
    void replayStopped();
    void errorOccurred(const QString& error);

private slots:
    void replayNext();

private:
    static qint64 timestampUsec(const PcapRecord& record);
    static double speedFactor(ReplaySpeed speed);
    bool consumeRecord(const PcapRecord& record, bool emitStats);

    QList<PcapRecord> m_records;
    PcapGlobalHeaderInfo m_header;
    PacketAnalyzer m_analyzer;
    QTimer m_timer;
    QString m_sourceName;
    int m_replayIndex=0;
    ReplaySpeed m_replaySpeed=ReplaySpeed::X1;
    bool m_replaying=false;
    int m_totalPacketCount=0;
    bool m_replayAvailable=true;
};
