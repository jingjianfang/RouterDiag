#include "TcpStreamReassembler.h"
#include <algorithm>

QString TcpStreamReassembler::endpoint(const QString& ip,quint16 port)
{
    return QStringLiteral("%1:%2").arg(ip).arg(port);
}

QString TcpStreamReassembler::flowKey(const ParsedPacket& packet)
{
    const QString a=endpoint(packet.sourceIp,packet.sourcePort);
    const QString b=endpoint(packet.destinationIp,packet.destinationPort);
    return a<b ? a+QStringLiteral("|")+b : b+QStringLiteral("|")+a;
}

void TcpStreamReassembler::reset()
{
    m_flows.clear();
}

void TcpStreamReassembler::consumePayload(DirectionState& state,quint32 sequence,const QByteArray& payload)
{
    if(payload.isEmpty())return;
    if(!state.initialized){
        state.initialized=true;
        state.nextSequence=sequence;
    }

    const qint64 delta=qint64(sequence)-qint64(state.nextSequence);
    if(delta>0){
        // Out-of-order segment. Keep it until the missing bytes arrive; never invent bytes.
        state.pending.insert(sequence,payload);
        state.gapObserved=true;
        return;
    }

    const qsizetype overlap=delta<0?qsizetype(-delta):0;
    if(overlap>=payload.size())return; // Full retransmission/already assembled.
    const QByteArray fresh=payload.mid(overlap);
    state.bytes+=fresh;
    state.nextSequence+=quint32(fresh.size());
    drainPending(state);
}

void TcpStreamReassembler::drainPending(DirectionState& state)
{
    bool progressed=true;
    while(progressed && !state.pending.isEmpty()){
        progressed=false;
        auto it=state.pending.begin();
        while(it!=state.pending.end()){
            const quint32 sequence=it.key();
            const QByteArray payload=it.value();
            const qint64 delta=qint64(sequence)-qint64(state.nextSequence);
            if(delta>0){++it;continue;}
            const qsizetype overlap=delta<0?qsizetype(-delta):0;
            it=state.pending.erase(it);
            if(overlap<payload.size()){
                const QByteArray fresh=payload.mid(overlap);
                state.bytes+=fresh;
                state.nextSequence+=quint32(fresh.size());
                progressed=true;
                break;
            }
        }
    }
}

void TcpStreamReassembler::consume(const ParsedPacket& packet)
{
    if(!packet.valid || packet.protocol!=QStringLiteral("TCP") || packet.payload.isEmpty())return;
    const QString key=flowKey(packet);
    const QString src=endpoint(packet.sourceIp,packet.sourcePort);
    const QString dst=endpoint(packet.destinationIp,packet.destinationPort);
    auto it=m_flows.find(key);
    if(it==m_flows.end()){
        FlowState flow;
        if(src<dst){flow.endpointA=src;flow.endpointB=dst;}
        else{flow.endpointA=dst;flow.endpointB=src;}
        it=m_flows.insert(key,flow);
    }
    DirectionState& direction=(src==it->endpointA)?it->aToB:it->bToA;
    consumePayload(direction,packet.sequence,packet.payload);
}

QList<ReassembledTcpDirection> TcpStreamReassembler::directions() const
{
    QList<ReassembledTcpDirection> out;
    for(auto it=m_flows.cbegin();it!=m_flows.cend();++it){
        const FlowState& flow=it.value();
        if(!flow.aToB.bytes.isEmpty())out.push_back({it.key(),flow.endpointA,flow.endpointB,flow.aToB.bytes,flow.aToB.gapObserved});
        if(!flow.bToA.bytes.isEmpty())out.push_back({it.key(),flow.endpointB,flow.endpointA,flow.bToA.bytes,flow.bToA.gapObserved});
    }
    std::sort(out.begin(),out.end(),[](const ReassembledTcpDirection& a,const ReassembledTcpDirection& b){
        if(a.flowKey!=b.flowKey)return a.flowKey<b.flowKey;
        return a.sourceEndpoint<b.sourceEndpoint;
    });
    return out;
}

QByteArray TcpStreamReassembler::bytesForPacketDirection(const ParsedPacket& packet) const
{
    if(packet.protocol!=QStringLiteral("TCP"))return {};
    const QString key=flowKey(packet);
    const auto it=m_flows.constFind(key);
    if(it==m_flows.cend())return {};
    const QString src=endpoint(packet.sourceIp,packet.sourcePort);
    return src==it->endpointA?it->aToB.bytes:it->bToA.bytes;
}
