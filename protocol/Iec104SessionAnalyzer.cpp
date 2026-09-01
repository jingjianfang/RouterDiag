#include "Iec104SessionAnalyzer.h"
#include "Iec104Analyzer.h"
#include <QHash>

namespace {
struct DirectionState {
    bool haveSend=false;
    quint16 firstSend=0;
    quint16 expectedSend=0;
    quint16 latestSend=0;
    quint16 latestNext=0;
    quint16 highestAck=0;
    bool haveAck=false;
    quint64 observedIFrames=0;
};
QString directionKey(const QString& src,const QString& dst){return src+QStringLiteral("->")+dst;}
quint16 nextSeq(quint16 s){return quint16((s+1u)&0x7fffu);}
int forwardDistance(quint16 from,quint16 to){return (int(to)-int(from)+32768)%32768;}
}

Iec104SessionSummary Iec104SessionAnalyzer::analyze(const QList<ReassembledTcpDirection>& directions)
{
    Iec104SessionSummary out;QHash<QString,DirectionState> states;
    for(const ReassembledTcpDirection& direction:directions){
        const QString key=directionKey(direction.sourceEndpoint,direction.destinationEndpoint);
        const QString reverse=directionKey(direction.destinationEndpoint,direction.sourceEndpoint);
        DirectionState& state=states[key];
        const QList<Iec104Frame> frames=Iec104Analyzer::parseStream(direction.bytes);
        for(const Iec104Frame& f:frames){
            if(!f.valid)continue;++out.validFrames;
            if(f.kind==Iec104FrameKind::U){
                if(f.uFunction==Iec104UFunction::StartDtAct)out.startDtActSeen=true;
                else if(f.uFunction==Iec104UFunction::StartDtCon)out.startDtConSeen=true;
                else if(f.uFunction==Iec104UFunction::StopDtAct)out.stopDtActSeen=true;
                else if(f.uFunction==Iec104UFunction::StopDtCon)out.stopDtConSeen=true;
                else if(f.uFunction==Iec104UFunction::TestFrAct)out.testFrActSeen=true;
                else if(f.uFunction==Iec104UFunction::TestFrCon)out.testFrConSeen=true;
                continue;
            }
            if(f.kind==Iec104FrameKind::I){
                if(!state.haveSend){state.haveSend=true;state.firstSend=f.sendSequence;state.expectedSend=nextSeq(f.sendSequence);}
                else if(f.sendSequence==quint16((state.expectedSend+32767)%32768)){++out.duplicateIFrameCount;}
                else if(f.sendSequence!=state.expectedSend){
                    const int ahead=forwardDistance(state.expectedSend,f.sendSequence);
                    if(ahead>0 && ahead<16384)++out.sequenceGapCount;else ++out.duplicateIFrameCount;
                    state.expectedSend=nextSeq(f.sendSequence);
                }else state.expectedSend=nextSeq(f.sendSequence);
                state.latestSend=f.sendSequence;state.latestNext=nextSeq(f.sendSequence);++state.observedIFrames;
            }
            if(f.kind==Iec104FrameKind::I || f.kind==Iec104FrameKind::S){
                DirectionState& peer=states[reverse];
                if(!peer.haveAck || forwardDistance(peer.highestAck,f.receiveSequence)<16384){peer.highestAck=f.receiveSequence;peer.haveAck=true;}
            }
        }
    }
    for(auto it=states.cbegin();it!=states.cend();++it){
        const DirectionState& state=it.value();if(!state.haveSend)continue;
        // N(R) is the next sequence the peer expects. If no N(R) was captured, count
        // all I frames seen in this direction as currently unconfirmed rather than reporting zero.
        const quint16 ackBase=state.haveAck?state.highestAck:state.firstSend;
        const int rawOutstanding=forwardDistance(ackBase,state.latestNext);
        // A capture may start in the middle of a long-lived IEC104 session. In that case an
        // old N(R) seen in the window must not make us claim hundreds/thousands of unconfirmed
        // I-frames that were never observed. Bound the estimate by I-frames actually captured.
        const quint64 outstanding=(rawOutstanding>=0&&rawOutstanding<16384)
            ?qMin(quint64(rawOutstanding),state.observedIFrames):0;
        out.outstandingIFrames=qMax(out.outstandingIFrames,outstanding);
        QString sequence=QStringLiteral("%1：最新N(S)=%2，下一N(S)=%3").arg(it.key()).arg(state.latestSend).arg(state.latestNext);
        sequence+=state.haveAck?QStringLiteral("，对端最高N(R)=%1，未确认估算=%2").arg(state.highestAck).arg(outstanding)
                               :QStringLiteral("，未观察到对端N(R)，未确认估算=%1").arg(outstanding);
        out.evidence<<sequence;
    }
    if(out.startDtActSeen)out.evidence<<QStringLiteral("IEC104 STARTDT act 已观察");
    if(out.startDtConSeen)out.evidence<<QStringLiteral("IEC104 STARTDT con 已观察");
    if(out.stopDtActSeen)out.evidence<<QStringLiteral("IEC104 STOPDT act 已观察");
    if(out.stopDtConSeen)out.evidence<<QStringLiteral("IEC104 STOPDT con 已观察");
    if(out.testFrActSeen)out.evidence<<QStringLiteral("IEC104 TESTFR act 已观察");
    if(out.testFrConSeen)out.evidence<<QStringLiteral("IEC104 TESTFR con 已观察");
    if(out.sequenceGapCount)out.evidence<<QStringLiteral("IEC104 I帧发送序号跳变：%1次").arg(out.sequenceGapCount);
    if(out.duplicateIFrameCount)out.evidence<<QStringLiteral("IEC104 I帧重复/回退：%1次").arg(out.duplicateIFrameCount);
    if(out.outstandingIFrames)out.evidence<<QStringLiteral("IEC104 当前最大未确认I帧估算：%1").arg(out.outstandingIFrames);
    return out;
}
