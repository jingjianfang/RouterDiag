#include "DualCaptureCorrelator.h"
#include <QCryptographicHash>
#include <QtMath>

void DualCaptureCorrelator::reset()
{
    m_unmatched.clear();m_matched=0;m_rangeMatched=0;m_streamMatched=0;m_delayTotal=0.0;m_delayMax=0.0;m_recentMatches.clear();
}

bool DualCaptureCorrelator::samePayload(const Observation& a,const Observation& b)
{
    return a.side!=b.side && a.sequence==b.sequence && a.payloadLength==b.payloadLength && a.payloadHash==b.payloadHash;
}

bool DualCaptureCorrelator::sequenceRangeOverlap(const Observation& a,const Observation& b)
{
    if(a.side==b.side||a.payloadLength==0||b.payloadLength==0)return false;
    const quint64 a0=a.sequence,a1=a0+a.payloadLength,b0=b.sequence,b1=b0+b.payloadLength;
    return a0<b1&&b0<a1;
}

bool DualCaptureCorrelator::streamFragmentMatch(const Observation& a,const Observation& b)
{
    if(!sequenceRangeOverlap(a,b)||a.payload.isEmpty()||b.payload.isEmpty())return false;
    const QByteArray& small=a.payload.size()<=b.payload.size()?a.payload:b.payload;
    const QByteArray& large=a.payload.size()>b.payload.size()?a.payload:b.payload;
    return small.size()>=8&&large.contains(small);
}

void DualCaptureCorrelator::trimOld(const QDateTime& now)
{
    if(!now.isValid())return;
    for(int i=m_unmatched.size()-1;i>=0;--i){
        if(m_unmatched.at(i).timestamp.isValid() && qAbs(m_unmatched.at(i).timestamp.msecsTo(now))>10000)m_unmatched.removeAt(i);
    }
    while(m_unmatched.size()>512)m_unmatched.removeFirst();
}

void DualCaptureCorrelator::consume(CaptureSide side,const ParsedPacket& packet)
{
    if(!packet.valid || packet.protocol!=QStringLiteral("TCP") || packet.tcpPayloadLength==0 || packet.payload.isEmpty())return;
    Observation now;now.side=side;now.sequence=packet.sequence;now.payloadLength=packet.tcpPayloadLength;
    now.payloadHash=QCryptographicHash::hash(packet.payload,QCryptographicHash::Sha1);now.payload=packet.payload;
    now.timestamp=packet.timestamp;now.sourceIp=packet.sourceIp;now.sourcePort=packet.sourcePort;now.destinationIp=packet.destinationIp;now.destinationPort=packet.destinationPort;
    trimOld(now.timestamp);
    int matchedIndex=-1;double bestDelay=1e100;int matchKind=0;
    // 1 exact payload, 2 sequence-range+fragment, 3 sequence-range only. The latter two handle GRO/GSO/segmentation differences.
    for(int pass=0;pass<3&&matchedIndex<0;++pass){
        for(int i=0;i<m_unmatched.size();++i){
            const Observation& other=m_unmatched.at(i);bool match=false;
            if(pass==0)match=samePayload(now,other);
            else if(pass==1)match=streamFragmentMatch(now,other);
            else match=sequenceRangeOverlap(now,other);
            if(!match)continue;
            double delay=0.0;if(now.timestamp.isValid()&&other.timestamp.isValid())delay=qAbs(double(other.timestamp.msecsTo(now.timestamp)));
            if(delay<=5000.0&&delay<bestDelay){bestDelay=delay;matchedIndex=i;matchKind=pass;}
        }
    }
    if(matchedIndex<0){m_unmatched<<now;return;}
    const Observation other=m_unmatched.takeAt(matchedIndex);++m_matched;if(matchKind==1)++m_streamMatched;else if(matchKind==2)++m_rangeMatched;m_delayTotal+=bestDelay;m_delayMax=qMax(m_delayMax,bestDelay);
    const Observation& lan=now.side==CaptureSide::TerminalLan?now:other;
    const Observation& wan=now.side==CaptureSide::Wan?now:other;
    const QString matchLabel=matchKind==0?QStringLiteral("精确Payload"):matchKind==1?QStringLiteral("TCP字节流片段"):QStringLiteral("TCP序号范围");
    const QString text=QStringLiteral("双点%12关联：SEQ=%1，%2 bytes，时间差=%3 ms；LAN %4:%5→%6:%7，WAN %8:%9→%10:%11")
        .arg(now.sequence).arg(now.payloadLength).arg(bestDelay,0,'f',1)
        .arg(lan.sourceIp).arg(lan.sourcePort).arg(lan.destinationIp).arg(lan.destinationPort)
        .arg(wan.sourceIp).arg(wan.sourcePort).arg(wan.destinationIp).arg(wan.destinationPort).arg(matchLabel);
    m_recentMatches<<text;while(m_recentMatches.size()>20)m_recentMatches.removeFirst();
}

DualCaptureCorrelationSummary DualCaptureCorrelator::summary() const
{
    DualCaptureCorrelationSummary s;s.matchedPackets=m_matched;s.rangeMatchedPackets=m_rangeMatched;s.streamMatchedPackets=m_streamMatched;
    for(const Observation& o:m_unmatched){if(o.side==CaptureSide::TerminalLan)++s.terminalOnlyPackets;else ++s.wanOnlyPackets;}
    if(m_matched){s.averageForwardDelayMs=m_delayTotal/double(m_matched);s.maximumForwardDelayMs=m_delayMax;}
    if(m_matched)s.evidence<<QStringLiteral("双点关联成功 %1 个Payload（精确=%2，字节流=%3，序号范围=%4），平均两侧时间差 %5 ms，最大 %6 ms")
        .arg(m_matched).arg(m_matched-m_streamMatched-m_rangeMatched).arg(m_streamMatched).arg(m_rangeMatched).arg(s.averageForwardDelayMs,0,'f',1).arg(s.maximumForwardDelayMs,0,'f',1);
    if(s.terminalOnlyPackets)s.evidence<<QStringLiteral("当前仍有 %1 个终端侧Payload未在WAN侧关联；抓包缺口、GRO/GSO或分段差异均可能造成未关联，不能单独等价为路由器丢包").arg(s.terminalOnlyPackets);
    if(s.wanOnlyPackets)s.evidence<<QStringLiteral("当前仍有 %1 个WAN侧Payload未在终端侧关联；需结合TCP序号范围与完整字节流继续判断").arg(s.wanOnlyPackets);
    s.evidence.append(m_recentMatches);return s;
}
