#pragma once
#include <QObject>
#include <QByteArray>
#include "PcapTypes.h"

class PcapStreamReader : public QObject {
    Q_OBJECT
public:
    explicit PcapStreamReader(QObject* parent=nullptr);
    void appendData(const QByteArray& data);
    void reset();
    bool finish(QString* error=nullptr);
    PcapGlobalHeaderInfo globalHeader() const { return m_header; }
signals:
    void globalHeaderReady(const PcapGlobalHeaderInfo& header);
    void packetReady(const PcapRecord& record);
    void rawBytesAccepted(const QByteArray& bytes);
    void streamError(const QString& message);
private:
    quint16 read16(const char* p) const;
    quint32 read32(const char* p) const;
    QByteArray m_buffer;
    PcapGlobalHeaderInfo m_header;
    bool m_haveHeader=false;
    bool m_failed=false;
    quint32 m_maxPacketSize=16*1024*1024;
};
