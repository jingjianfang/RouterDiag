#pragma once

#include <QByteArray>
#include <QDate>
#include <QTime>
#include <QtGlobal>

// Incrementally converts `tcpdump -xx -n -l` text into a Classic PCAP byte stream.
// feed() returns only newly completed PCAP bytes, so callers can pass them straight
// to PcapStreamReader and display packets while tcpdump is still running.
class TcpdumpTextStreamParser {
public:
    void reset(const QDate& fallbackDate=QDate());
    QByteArray feed(const QByteArray& chunk);
    QByteArray finish();
    int packetCount() const{return m_packetCount;}
    int skippedPacketCount() const{return m_skippedPacketCount;}

private:
    QByteArray processLine(const QString& line);
    QByteArray finishCurrent(bool force=false);

    QByteArray m_lineBuffer;
    QDate m_date;
    QTime m_previousTime;
    QTime m_currentTime;
    int m_currentUsec=0;
    QByteArray m_frame;
    bool m_haveCurrent=false;
    bool m_offsetGap=false;
    quint32 m_linkType=0;
    bool m_headerWritten=false;
    int m_packetCount=0;
    int m_skippedPacketCount=0;
};
