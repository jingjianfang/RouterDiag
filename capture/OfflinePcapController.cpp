#include "OfflinePcapController.h"
#include "PcapStreamReader.h"
#include "PacketParser.h"
#include <QFile>
#include <QCoreApplication>
#include <QEventLoop>
#include <QtMath>
#include <limits>

namespace {

struct PcapngInterfaceInfo {
    quint32 linkType=0;
    quint32 snapLen=0;
    quint8 tsResolution=6; // pcapng default: 10^-6 seconds
};

quint16 pcapngRead16(const char* p,bool little){
    const auto* u=reinterpret_cast<const unsigned char*>(p);
    return little ? quint16(u[0] | (u[1]<<8)) : quint16((u[0]<<8)|u[1]);
}
quint32 pcapngRead32(const char* p,bool little){
    const auto* u=reinterpret_cast<const unsigned char*>(p);
    if(little)return quint32(u[0])|(quint32(u[1])<<8)|(quint32(u[2])<<16)|(quint32(u[3])<<24);
    return (quint32(u[0])<<24)|(quint32(u[1])<<16)|(quint32(u[2])<<8)|quint32(u[3]);
}

bool parsePcapng(const QByteArray& data,PcapGlobalHeaderInfo* header,QList<PcapRecord>* records,QString* error){
    if(!data.startsWith(QByteArray::fromHex("0A0D0D0A"))){
        if(error)*error=QStringLiteral("PCAPNG section header is missing");
        return false;
    }
    bool little=true;
    bool haveSection=false;
    QList<PcapngInterfaceInfo> interfaces;
    qsizetype pos=0;
    quint32 activeLinkType=0;
    quint32 activeSnapLen=0;

    while(pos<data.size()){
        if(data.size()-pos<12){if(error)*error=QStringLiteral("PCAPNG block header is truncated");return false;}
        const char* block=data.constData()+pos;
        const QByteArray rawType=data.mid(pos,4);
        const bool isSection=(rawType==QByteArray::fromHex("0A0D0D0A"));
        if(isSection){
            if(data.size()-pos<16){if(error)*error=QStringLiteral("PCAPNG section header is truncated");return false;}
            const QByteArray bom=data.mid(pos+8,4);
            if(bom==QByteArray::fromHex("4D3C2B1A"))little=true;
            else if(bom==QByteArray::fromHex("1A2B3C4D"))little=false;
            else {if(error)*error=QStringLiteral("PCAPNG byte-order magic is invalid");return false;}
            haveSection=true;
            interfaces.clear();
        }else if(!haveSection){
            if(error)*error=QStringLiteral("PCAPNG data appears before a section header");return false;
        }

        const quint32 type=isSection?0x0A0D0D0Au:pcapngRead32(block,little);
        const quint32 totalLength=pcapngRead32(block+4,little);
        if(totalLength<12 || (totalLength%4)!=0 || quint64(pos)+totalLength>quint64(data.size())){
            if(error)*error=QStringLiteral("PCAPNG block length is invalid");return false;
        }
        if(pcapngRead32(block+totalLength-4,little)!=totalLength){
            if(error)*error=QStringLiteral("PCAPNG block length trailer does not match");return false;
        }

        if(type==0x00000001u){ // Interface Description Block
            if(totalLength<20){if(error)*error=QStringLiteral("PCAPNG interface block is truncated");return false;}
            PcapngInterfaceInfo info;
            info.linkType=pcapngRead16(block+8,little);
            info.snapLen=pcapngRead32(block+12,little);
            qsizetype opt=16;
            const qsizetype optEnd=qsizetype(totalLength)-4;
            while(opt+4<=optEnd){
                const quint16 code=pcapngRead16(block+opt,little);
                const quint16 len=pcapngRead16(block+opt+2,little);
                opt+=4;
                if(code==0)break;
                if(opt+len>optEnd){if(error)*error=QStringLiteral("PCAPNG interface option is truncated");return false;}
                if(code==9 && len>=1)info.tsResolution=quint8(block[opt]);
                opt+=(len+3)&~3;
            }
            interfaces.append(info);
        }else if(type==0x00000006u){ // Enhanced Packet Block
            if(totalLength<32){if(error)*error=QStringLiteral("PCAPNG Enhanced Packet Block is truncated");return false;}
            const quint32 interfaceId=pcapngRead32(block+8,little);
            if(interfaceId>=quint32(interfaces.size())){if(error)*error=QStringLiteral("PCAPNG packet references an unknown interface");return false;}
            const auto& iface=interfaces.at(int(interfaceId));
            const quint32 capLen=pcapngRead32(block+20,little);
            const quint32 origLen=pcapngRead32(block+24,little);
            const quint64 padded=(quint64(capLen)+3u)&~quint64(3u);
            if(28u+padded+4u>totalLength){if(error)*error=QStringLiteral("PCAPNG Enhanced Packet Block payload is truncated");return false;}
            if(activeLinkType==0){activeLinkType=iface.linkType;activeSnapLen=iface.snapLen;}
            else if(activeLinkType!=iface.linkType){if(error)*error=QStringLiteral("PCAPNG contains packet interfaces with different link types");return false;}

            const quint64 rawTs=(quint64(pcapngRead32(block+12,little))<<32)|pcapngRead32(block+16,little);
            long double unitsPerSecond=1.0L;
            const quint8 resol=iface.tsResolution;
            if(resol&0x80){
                const int exp=int(resol&0x7f);
                for(int i=0;i<exp;i++)unitsPerSecond*=2.0L;
            }else{
                for(int i=0;i<int(resol);i++)unitsPerSecond*=10.0L;
            }
            if(unitsPerSecond<=0.0L){if(error)*error=QStringLiteral("PCAPNG timestamp resolution is invalid");return false;}
            const quint64 sec=quint64(static_cast<long double>(rawTs)/unitsPerSecond);
            const long double fractional=static_cast<long double>(rawTs)-static_cast<long double>(sec)*unitsPerSecond;
            const quint64 nanos=quint64((fractional*1000000000.0L)/unitsPerSecond);

            PcapRecord r;
            r.tsSec=quint32(qMin<quint64>(sec,std::numeric_limits<quint32>::max()));
            r.tsFraction=quint32(qMin<quint64>(nanos,999999999u));
            r.nanosecondResolution=true;
            r.includedLength=capLen;
            r.originalLength=origLen;
            r.data=QByteArray(block+28,int(capLen));
            records->append(r);
        }
        pos+=totalLength;
    }

    if(interfaces.isEmpty()){if(error)*error=QStringLiteral("PCAPNG contains no interface description");return false;}
    if(activeLinkType==0){activeLinkType=interfaces.first().linkType;activeSnapLen=interfaces.first().snapLen;}
    header->valid=true;
    header->littleEndian=little;
    header->nanosecondResolution=true;
    header->versionMajor=1;
    header->versionMinor=0;
    header->snapLen=activeSnapLen;
    header->linkType=activeLinkType;
    return true;
}

}


OfflinePcapController::OfflinePcapController(QObject* parent):QObject(parent){
    m_timer.setSingleShot(true);
    connect(&m_timer,&QTimer::timeout,this,&OfflinePcapController::replayNext);
}

bool OfflinePcapController::loadFile(const QString& path,QString* error){
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)){
        if(error)*error=f.errorString();
        return false;
    }

    stopReplay();
    m_records.clear();
    m_header=PcapGlobalHeaderInfo{};
    m_analyzer.reset();
    m_sourceName=path;
    m_totalPacketCount=0;
    constexpr qint64 MaxReplayCacheBytes=64LL*1024*1024;
    constexpr qint64 ChunkSize=1024*1024;
    m_replayAvailable=(f.size()<=MaxReplayCacheBytes);

    QString parseError;
    qint64 lastUiYield=0;
    auto acceptRecord=[&](const PcapRecord& record){
        if(m_replayAvailable)m_records.append(record);
        ++m_totalPacketCount;
        consumeRecord(record,false);
        if((m_totalPacketCount%256)==0){
            emit loadProgress(f.pos(),f.size(),m_totalPacketCount);
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,5);
        }
    };
    auto supportedLink=[](quint32 link){
        return link==PcapLinkType::Ethernet || link==PcapLinkType::LinuxSll ||
               link==PcapLinkType::LinuxSll2 || link==PcapLinkType::Raw;
    };

    const QByteArray magic=f.peek(4);
    if(magic==QByteArray::fromHex("0A0D0D0A")){
        bool little=true;
        bool haveSection=false;
        QList<PcapngInterfaceInfo> interfaces;
        quint32 activeLinkType=0;
        quint32 activeSnapLen=0;
        while(!f.atEnd()){
            QByteArray block=f.read(12);
            if(block.isEmpty())break;
            if(block.size()!=12){parseError=QStringLiteral("PCAPNG block header is truncated");break;}
            const bool isSection=(block.left(4)==QByteArray::fromHex("0A0D0D0A"));
            if(isSection){
                const QByteArray bom=block.mid(8,4);
                if(bom==QByteArray::fromHex("4D3C2B1A"))little=true;
                else if(bom==QByteArray::fromHex("1A2B3C4D"))little=false;
                else {parseError=QStringLiteral("PCAPNG byte-order magic is invalid");break;}
                haveSection=true;interfaces.clear();
            }else if(!haveSection){parseError=QStringLiteral("PCAPNG data appears before a section header");break;}

            const quint32 type=isSection?0x0A0D0D0Au:pcapngRead32(block.constData(),little);
            const quint32 totalLength=pcapngRead32(block.constData()+4,little);
            if(totalLength<12 || (totalLength%4)!=0 || totalLength>128u*1024u*1024u){parseError=QStringLiteral("PCAPNG block length is invalid");break;}
            const qint64 remain=qint64(totalLength)-12;
            const QByteArray tail=f.read(remain);
            if(tail.size()!=remain){parseError=QStringLiteral("PCAPNG block payload is truncated");break;}
            block+=tail;
            if(pcapngRead32(block.constData()+totalLength-4,little)!=totalLength){parseError=QStringLiteral("PCAPNG block length trailer does not match");break;}

            const char* raw=block.constData();
            if(type==0x00000001u){
                if(totalLength<20){parseError=QStringLiteral("PCAPNG interface block is truncated");break;}
                PcapngInterfaceInfo info;
                info.linkType=pcapngRead16(raw+8,little);info.snapLen=pcapngRead32(raw+12,little);
                qsizetype opt=16,optEnd=qsizetype(totalLength)-4;
                while(opt+4<=optEnd){
                    const quint16 code=pcapngRead16(raw+opt,little),len=pcapngRead16(raw+opt+2,little);opt+=4;
                    if(code==0)break;
                    if(opt+len>optEnd){parseError=QStringLiteral("PCAPNG interface option is truncated");break;}
                    if(code==9 && len>=1)info.tsResolution=quint8(raw[opt]);
                    opt+=(len+3)&~3;
                }
                if(!parseError.isEmpty())break;
                interfaces.append(info);
            }else if(type==0x00000006u){
                if(totalLength<32){parseError=QStringLiteral("PCAPNG Enhanced Packet Block is truncated");break;}
                const quint32 interfaceId=pcapngRead32(raw+8,little);
                if(interfaceId>=quint32(interfaces.size())){parseError=QStringLiteral("PCAPNG packet references an unknown interface");break;}
                const auto& iface=interfaces.at(int(interfaceId));
                if(!supportedLink(iface.linkType)){parseError=QStringLiteral("暂不支持该 PCAP 链路类型: %1").arg(iface.linkType);break;}
                const quint32 capLen=pcapngRead32(raw+20,little),origLen=pcapngRead32(raw+24,little);
                const quint64 padded=(quint64(capLen)+3u)&~quint64(3u);
                if(28u+padded+4u>totalLength){parseError=QStringLiteral("PCAPNG Enhanced Packet Block payload is truncated");break;}
                if(activeLinkType==0){activeLinkType=iface.linkType;activeSnapLen=iface.snapLen;}
                else if(activeLinkType!=iface.linkType){parseError=QStringLiteral("PCAPNG contains packet interfaces with different link types");break;}
                m_header.valid=true;m_header.littleEndian=little;m_header.nanosecondResolution=true;m_header.versionMajor=1;m_header.versionMinor=0;m_header.snapLen=activeSnapLen;m_header.linkType=activeLinkType;

                const quint64 rawTs=(quint64(pcapngRead32(raw+12,little))<<32)|pcapngRead32(raw+16,little);
                long double unitsPerSecond=1.0L;const quint8 resol=iface.tsResolution;
                if(resol&0x80){for(int i=0;i<int(resol&0x7f);++i)unitsPerSecond*=2.0L;}
                else {for(int i=0;i<int(resol);++i)unitsPerSecond*=10.0L;}
                if(unitsPerSecond<=0.0L){parseError=QStringLiteral("PCAPNG timestamp resolution is invalid");break;}
                const quint64 sec=quint64(static_cast<long double>(rawTs)/unitsPerSecond);
                const long double fractional=static_cast<long double>(rawTs)-static_cast<long double>(sec)*unitsPerSecond;
                const quint64 nanos=quint64((fractional*1000000000.0L)/unitsPerSecond);
                PcapRecord record;record.tsSec=quint32(qMin<quint64>(sec,std::numeric_limits<quint32>::max()));record.tsFraction=quint32(qMin<quint64>(nanos,999999999u));record.nanosecondResolution=true;record.includedLength=capLen;record.originalLength=origLen;record.data=QByteArray(raw+28,int(capLen));
                acceptRecord(record);
            }
            if(f.pos()-lastUiYield>=ChunkSize){lastUiYield=f.pos();emit loadProgress(f.pos(),f.size(),m_totalPacketCount);QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,5);}
        }
        if(parseError.isEmpty()){
            if(interfaces.isEmpty())parseError=QStringLiteral("PCAPNG contains no interface description");
            else if(!m_header.valid){
                const auto& iface=interfaces.first();
                if(!supportedLink(iface.linkType))parseError=QStringLiteral("暂不支持该 PCAP 链路类型: %1").arg(iface.linkType);
                else {m_header.valid=true;m_header.littleEndian=little;m_header.nanosecondResolution=true;m_header.versionMajor=1;m_header.versionMinor=0;m_header.snapLen=iface.snapLen;m_header.linkType=iface.linkType;}
            }
        }
    }else{
        PcapStreamReader reader;
        connect(&reader,&PcapStreamReader::globalHeaderReady,this,[&](const PcapGlobalHeaderInfo& header){
            m_header=header;
            if(!supportedLink(header.linkType) && parseError.isEmpty())parseError=QStringLiteral("暂不支持该 PCAP 链路类型: %1").arg(header.linkType);
        });
        connect(&reader,&PcapStreamReader::packetReady,this,[&](const PcapRecord& record){if(parseError.isEmpty())acceptRecord(record);});
        connect(&reader,&PcapStreamReader::streamError,this,[&](const QString& e){if(parseError.isEmpty())parseError=e;});
        while(!f.atEnd() && parseError.isEmpty()){
            const QByteArray chunk=f.read(ChunkSize);
            if(chunk.isEmpty() && f.error()!=QFile::NoError){parseError=f.errorString();break;}
            reader.appendData(chunk);
            emit loadProgress(f.pos(),f.size(),m_totalPacketCount);
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,5);
        }
        if(parseError.isEmpty())reader.finish(&parseError);
    }

    if(!parseError.isEmpty()){
        m_records.clear();m_header=PcapGlobalHeaderInfo{};m_analyzer.reset();m_totalPacketCount=0;m_replayAvailable=false;
        if(error)*error=parseError;
        return false;
    }
    emit loadProgress(f.size(),f.size(),m_totalPacketCount);
    emit statsUpdated(m_analyzer.stats());
    emit loaded(m_sourceName,m_totalPacketCount,m_header);
    return true;
}

bool OfflinePcapController::loadData(const QByteArray& data,QString* error,const QString& sourceName){
    stopReplay();
    m_records.clear();
    m_header=PcapGlobalHeaderInfo{};
    m_analyzer.reset();
    m_sourceName=sourceName;
    m_totalPacketCount=0;
    m_replayAvailable=true;

    QString parseError;
    if(data.startsWith(QByteArray::fromHex("0A0D0D0A"))){
        parsePcapng(data,&m_header,&m_records,&parseError);
    }else{
        PcapStreamReader reader;
        connect(&reader,&PcapStreamReader::globalHeaderReady,this,[this](const PcapGlobalHeaderInfo& h){m_header=h;});
        connect(&reader,&PcapStreamReader::packetReady,this,[this](const PcapRecord& r){m_records.append(r);});
        connect(&reader,&PcapStreamReader::streamError,this,[&parseError](const QString& e){if(parseError.isEmpty())parseError=e;});
        reader.appendData(data);
        if(parseError.isEmpty())reader.finish(&parseError);
    }

    if(!parseError.isEmpty()){
        m_records.clear();m_header=PcapGlobalHeaderInfo{};
        if(error)*error=parseError;
        return false;
    }
    if(m_header.linkType!=PcapLinkType::Ethernet && m_header.linkType!=PcapLinkType::LinuxSll && m_header.linkType!=PcapLinkType::LinuxSll2 && m_header.linkType!=PcapLinkType::Raw){
        const QString e=QStringLiteral("暂不支持该 PCAP 链路类型: %1").arg(m_header.linkType);
        m_records.clear();m_header=PcapGlobalHeaderInfo{};
        if(error)*error=e;
        return false;
    }
    m_totalPacketCount=m_records.size();
    emit loaded(m_sourceName,m_totalPacketCount,m_header);
    return true;
}

void OfflinePcapController::clear(){
    stopReplay();
    m_records.clear();
    m_header=PcapGlobalHeaderInfo{};
    m_analyzer.reset();
    m_sourceName.clear();
    m_replayIndex=0;
    m_totalPacketCount=0;
    m_replayAvailable=true;
}

bool OfflinePcapController::consumeRecord(const PcapRecord& record,bool emitStats){
    const ParsedPacket p=PacketParser::parse(record,m_header.linkType);
    if(!p.valid)return false;
    m_analyzer.consume(p);
    emit packetReady(p);
    if(emitStats)emit statsUpdated(m_analyzer.stats());
    return true;
}

void OfflinePcapController::analyzeAll(){
    if(!m_header.valid){emit errorOccurred(QStringLiteral("尚未导入抓包文件"));return;}
    if(!m_replayAvailable){emit statsUpdated(m_analyzer.stats());return;}
    stopReplay();
    m_analyzer.reset();
    for(const PcapRecord& r:m_records)consumeRecord(r,false);
    emit statsUpdated(m_analyzer.stats());
}

double OfflinePcapController::speedFactor(ReplaySpeed speed){
    switch(speed){
    case ReplaySpeed::X5:return 5.0;
    case ReplaySpeed::X10:return 10.0;
    case ReplaySpeed::Fastest:return std::numeric_limits<double>::infinity();
    case ReplaySpeed::X1:
    default:return 1.0;
    }
}

qint64 OfflinePcapController::timestampUsec(const PcapRecord& r){
    const qint64 fraction=r.nanosecondResolution?qint64(r.tsFraction)/1000:qint64(r.tsFraction);
    return qint64(r.tsSec)*1000000LL+fraction;
}

void OfflinePcapController::startReplay(ReplaySpeed speed){
    if(!m_header.valid){emit errorOccurred(QStringLiteral("尚未导入抓包文件"));return;}
    if(!m_replayAvailable){emit errorOccurred(QStringLiteral("文件较大，已采用流式分析以避免占满内存；如需按时间回放请先裁剪为较小 PCAP"));return;}
    stopReplay();
    m_analyzer.reset();
    m_replayIndex=0;
    m_replaySpeed=speed;
    m_replaying=true;
    emit replayStarted();
    m_timer.start(0);
}

void OfflinePcapController::stopReplay(){
    if(!m_replaying)return;
    m_timer.stop();
    m_replaying=false;
    emit replayStopped();
}

void OfflinePcapController::replayNext(){
    if(!m_replaying)return;
    if(m_replayIndex>=m_records.size()){
        m_replaying=false;
        emit statsUpdated(m_analyzer.stats());
        emit replayFinished();
        return;
    }

    if(m_replaySpeed==ReplaySpeed::Fastest){
        constexpr int BatchSize=200;
        const int end=qMin(m_replayIndex+BatchSize,m_records.size());
        while(m_replayIndex<end)consumeRecord(m_records[m_replayIndex++],false);
        emit statsUpdated(m_analyzer.stats());
        m_timer.start(0);
        return;
    }

    const int current=m_replayIndex;
    consumeRecord(m_records[m_replayIndex++],true);
    if(m_replayIndex>=m_records.size()){
        m_timer.start(0);
        return;
    }
    qint64 delta=timestampUsec(m_records[m_replayIndex])-timestampUsec(m_records[current]);
    if(delta<0)delta=0;
    const double factor=speedFactor(m_replaySpeed);
    qint64 delayMs=qRound64((double(delta)/1000.0)/factor);
    delayMs = qBound<qint64>(
        qint64(0),
        delayMs,
        qint64(std::numeric_limits<int>::max())
    );
    m_timer.start(int(delayMs));
}
