#include "PcapStreamReader.h"
#include <QList>

PcapStreamReader::PcapStreamReader(QObject* parent):QObject(parent){}

quint16 PcapStreamReader::read16(const char* p) const {
    const auto* u=reinterpret_cast<const unsigned char*>(p);
    return m_header.littleEndian ? quint16(u[0] | (u[1]<<8)) : quint16((u[0]<<8)|u[1]);
}
quint32 PcapStreamReader::read32(const char* p) const {
    const auto* u=reinterpret_cast<const unsigned char*>(p);
    if(m_header.littleEndian) return quint32(u[0])|(quint32(u[1])<<8)|(quint32(u[2])<<16)|(quint32(u[3])<<24);
    return (quint32(u[0])<<24)|(quint32(u[1])<<16)|(quint32(u[2])<<8)|quint32(u[3]);
}
void PcapStreamReader::appendData(const QByteArray& data){
    if(m_failed||data.isEmpty()) return;
    m_buffer.append(data);
    while(true){
        if(!m_haveHeader){
            if(m_buffer.size()<4) return;
            const QList<QByteArray> magics={QByteArray::fromHex("d4c3b2a1"),QByteArray::fromHex("a1b2c3d4"),QByteArray::fromHex("4d3cb2a1"),QByteArray::fromHex("a1b23c4d")};
            int first=-1;
            for(const auto& candidate:magics){int pos=m_buffer.indexOf(candidate);if(pos>=0&&(first<0||pos<first))first=pos;}
            if(first>0)m_buffer.remove(0,first);
            else if(first<0){if(m_buffer.size()>4096){m_failed=true;emit streamError(QStringLiteral("Classic PCAP magic not found in capture stream"));return;}return;}
            if(m_buffer.size()<24) return;
            QByteArray magic=m_buffer.left(4);
            if(magic==QByteArray::fromHex("d4c3b2a1")){m_header.littleEndian=true;m_header.nanosecondResolution=false;}
            else if(magic==QByteArray::fromHex("a1b2c3d4")){m_header.littleEndian=false;m_header.nanosecondResolution=false;}
            else if(magic==QByteArray::fromHex("4d3cb2a1")){m_header.littleEndian=true;m_header.nanosecondResolution=true;}
            else if(magic==QByteArray::fromHex("a1b23c4d")){m_header.littleEndian=false;m_header.nanosecondResolution=true;}
            else {m_failed=true;emit streamError(QStringLiteral("Invalid Classic PCAP magic"));return;}
            m_header.versionMajor=read16(m_buffer.constData()+4);m_header.versionMinor=read16(m_buffer.constData()+6);
            m_header.snapLen=read32(m_buffer.constData()+16);m_header.linkType=read32(m_buffer.constData()+20);m_header.valid=true;
            QByteArray accepted=m_buffer.left(24);m_buffer.remove(0,24);m_haveHeader=true;
            emit rawBytesAccepted(accepted);emit globalHeaderReady(m_header);
        }
        if(m_buffer.size()<16) return;
        PcapRecord r; const char* p=m_buffer.constData();
        r.tsSec=read32(p);r.tsFraction=read32(p+4);r.includedLength=read32(p+8);r.originalLength=read32(p+12);r.nanosecondResolution=m_header.nanosecondResolution;
        if(r.includedLength>m_maxPacketSize || (m_header.snapLen && r.includedLength>m_header.snapLen)) {m_failed=true;emit streamError(QStringLiteral("PCAP packet length is unreasonable: %1").arg(r.includedLength));return;}
        const qint64 total=16+qint64(r.includedLength); if(m_buffer.size()<total) return;
        QByteArray accepted=m_buffer.left(int(total)); r.data=m_buffer.mid(16,int(r.includedLength)); m_buffer.remove(0,int(total));
        emit rawBytesAccepted(accepted);emit packetReady(r);
    }
}
bool PcapStreamReader::finish(QString* error){
    if(m_failed){if(error)*error=QStringLiteral("PCAP stream is already in failed state");return false;}
    if(!m_haveHeader){if(error)*error=QStringLiteral("PCAP global header is missing or incomplete");return false;}
    if(!m_buffer.isEmpty()){if(error)*error=QStringLiteral("PCAP stream is truncated: %1 trailing bytes remain").arg(m_buffer.size());return false;}
    return true;
}
void PcapStreamReader::reset(){m_buffer.clear();m_header=PcapGlobalHeaderInfo{};m_haveHeader=false;m_failed=false;}
