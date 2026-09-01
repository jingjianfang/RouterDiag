#include "ChannelAnalyzer.h"
#include <algorithm>

namespace {
QString ep(const QString& ip,quint16 port)
{
    return QStringLiteral("%1:%2").arg(ip).arg(port);
}

bool explicitPingReachabilityFailure(const PingResult& ping)
{
    return ping.failureKind==PingFailureKind::NetworkUnreachable
        || ping.failureKind==PingFailureKind::DestinationHostUnreachable
        || ping.failureKind==PingFailureKind::AddressResolutionFailed;
}

bool sessionHasPayload(const TcpSessionEvidence& s)
{
    return (s.payloadPacketsFromInitiator+s.payloadPacketsFromResponder)>0;
}

bool betterMainSession(const TcpSessionEvidence& candidate,const TcpSessionEvidence& current)
{
    // Lexicographic priority. Do not add epoch time into a numeric score: a new empty
    // connection must never outrank an established session that is actually carrying data.
    if(sessionHasPayload(candidate)!=sessionHasPayload(current))return sessionHasPayload(candidate);
    if(candidate.handshakeComplete!=current.handshakeComplete)return candidate.handshakeComplete;
    if((candidate.synAckCount>0)!=(current.synAckCount>0))return candidate.synAckCount>0;
    if(candidate.lastSeen.isValid()!=current.lastSeen.isValid())return candidate.lastSeen.isValid();
    if(candidate.lastSeen!=current.lastSeen)return candidate.lastSeen>current.lastSeen;
    return candidate.firstSeen>current.firstSeen;
}

int mainSessionIndex(const QList<TcpSessionEvidence>& sessions)
{
    if(sessions.isEmpty())return -1;
    int best=0;
    for(int i=1;i<sessions.size();++i)
        if(betterMainSession(sessions.at(i),sessions.at(best)))best=i;
    return best;
}

LayerDiagnosis diagnoseSession(const TcpSessionEvidence& s)
{
    LayerDiagnosis d;
    d.layer=QStringLiteral("TCP_SESSION");
    const QString initiator=ep(s.initiatorIp,s.initiatorPort);
    const QString responder=ep(s.responderIp,s.responderPort);
    const QString flow=s.initiatorKnown
        ? QStringLiteral("%1 → %2").arg(initiator,responder)
        : QStringLiteral("%1 ↔ %2").arg(initiator,responder);
    const quint64 initiatorPayload=s.payloadPacketsFromInitiator;
    const quint64 responderPayload=s.payloadPacketsFromResponder;
    const bool anyPayload=initiatorPayload>0 || responderPayload>0;
    const bool bothPayload=initiatorPayload>0 && responderPayload>0;
    const bool anyRst=s.rstFromInitiator>0 || s.rstFromResponder>0;
    const bool anyFin=s.finFromInitiator>0 || s.finFromResponder>0;

    if(anyRst){
        const QString resetter=!s.firstRstIp.isEmpty()?ep(s.firstRstIp,s.firstRstPort):(s.rstFromResponder>0?responder:initiator);
        if(s.initiatorKnown && resetter==responder && !s.handshakeComplete && s.synCount>0 && s.synAckCount==0){
            d.state=LayerState::Error;d.confidence=Confidence::High;
            d.conclusion=QStringLiteral("TCP连接被拒绝：%1 对连接请求返回 RST").arg(responder);
            d.evidence<<QStringLiteral("%1 | SYN → RST/RST,ACK").arg(flow);
            d.suggestions<<QStringLiteral("目标IP可到达但端口拒绝连接；检查 %1 的业务服务是否启动、端口是否监听及访问控制策略").arg(responder);
        }else if(bothPayload){
            d.state=LayerState::Warning;d.confidence=Confidence::High;
            d.conclusion=QStringLiteral("TCP业务完成后连接被重置：此前已观察到双向业务数据，随后 %1 发送 RST").arg(resetter);
            d.evidence<<QStringLiteral("%1 | 双向Payload存在，RST发生在业务数据之后").arg(flow);
            d.suggestions<<QStringLiteral("若业务本身已完成，可结合应用日志确认RST是否为主动快速释放；若频繁出现则检查协议状态和超时设置");
        }else{
            d.state=LayerState::Error;d.confidence=Confidence::High;
            d.conclusion=QStringLiteral("TCP连接异常重置：%1 主动发送 RST").arg(resetter);
            if(s.handshakeComplete)d.evidence<<QStringLiteral("%1 | TCP已建立但尚无完整双向业务证据，随后由 %2 重置").arg(flow,resetter);
            else if(anyPayload)d.evidence<<QStringLiteral("%1 | 仅观察到部分/单向业务数据，随后由 %2 发送 RST").arg(flow,resetter);
            else d.evidence<<QStringLiteral("%1 | 观察到 %2 发送 RST，当前窗口未形成完整握手证据").arg(flow,resetter);
            d.suggestions<<QStringLiteral("检查 %1 对应应用服务、协议状态和主动重置原因").arg(resetter);
        }
        return d;
    }

    if(anyFin && (s.handshakeComplete || anyPayload)){
        const QString closer=!s.firstFinIp.isEmpty()?ep(s.firstFinIp,s.firstFinPort):(s.finFromInitiator>0?initiator:responder);
        const bool bothFin=s.finFromInitiator>0 && s.finFromResponder>0;
        if(bothPayload){
            d.state=LayerState::Normal;d.confidence=bothFin?Confidence::High:Confidence::Medium;
            d.conclusion=bothFin?QStringLiteral("TCP业务完成并正常关闭：%1 发起 FIN，已观察到双方关闭过程").arg(closer)
                                :QStringLiteral("TCP业务已双向传输，随后由 %1 发起正常FIN释放").arg(closer);
        }else{
            d.state=LayerState::Warning;d.confidence=Confidence::Medium;
            d.conclusion=QStringLiteral("观察到TCP FIN：%1 发起连接释放，但缺少双向业务数据证据；FIN只能证明连接释放，不能证明业务正常").arg(closer);
            d.suggestions<<QStringLiteral("确认业务是否要求应答，并检查抓包窗口内另一方向Payload是否缺失");
        }
        d.evidence<<QStringLiteral("%1 | FIN主动方=%2").arg(flow,closer);
        if(!s.handshakeComplete)d.evidence<<QStringLiteral("抓包窗口未包含完整握手");
        return d;
    }

    if(s.synCount>0 && s.synAckCount==0){
        d.state=LayerState::Warning;d.confidence=s.synCount>=3?Confidence::High:Confidence::Medium;
        d.conclusion=QStringLiteral("TCP连接未应答：%1 未对 SYN 连接请求返回 SYN/ACK 或 RST").arg(responder);
        d.evidence<<QStringLiteral("%1 | 已发送 %2次 SYN，未观察到应答").arg(flow).arg(s.synCount);
        d.suggestions<<QStringLiteral("检查 %1 是否在线、路由/回程、防火墙或ACL是否丢弃连接请求").arg(responder);
        return d;
    }

    if(s.synAckCount>0 && !s.handshakeComplete){
        d.state=LayerState::Warning;d.confidence=Confidence::High;
        d.conclusion=QStringLiteral("TCP握手未完成：%1 已返回 SYN/ACK，但 %2 未完成最终 ACK").arg(responder,initiator);
        d.evidence<<QStringLiteral("%1 | %2SYN/ACK，未观察到最终 ACK")
                        .arg(flow,s.synCount>0?QStringLiteral("SYN → "):QString());
        d.suggestions<<QStringLiteral("检查 %1 到 %2 的回程链路、主机状态或抓包窗口是否覆盖完整握手").arg(responder,initiator);
        return d;
    }

    if(s.handshakeComplete){
        if(bothPayload){
            d.state=LayerState::Normal;d.confidence=Confidence::High;
            if(s.synCount>0)
                d.conclusion=QStringLiteral("TCP连接正常：%1，三次握手完成并观察到双向业务数据").arg(flow);
            else
                d.conclusion=QStringLiteral("TCP连接正常：%1，已观察到 SYN/ACK→ACK 及双向业务数据；抓包窗口未包含初始 SYN").arg(flow);
            d.evidence<<QStringLiteral("发起方载荷 %1 包/%2 bytes；应答方载荷 %3 包/%4 bytes")
                            .arg(s.payloadPacketsFromInitiator).arg(s.payloadBytesFromInitiator)
                            .arg(s.payloadPacketsFromResponder).arg(s.payloadBytesFromResponder);
        }else if(anyPayload){
            d.state=LayerState::Warning;d.confidence=Confidence::Medium;
            const QString dataSide=s.payloadPacketsFromInitiator>0?initiator:responder;
            d.conclusion=QStringLiteral("TCP连接已建立，但当前抓包窗口仅观察到单向业务数据：%1").arg(dataSide);
            d.evidence<<QStringLiteral("%1 | 建链证据存在，Payload 当前仅见单向").arg(flow);
            d.suggestions<<QStringLiteral("结合业务周期继续抓包，确认另一方向是否存在业务应答");
        }else{
            d.state=LayerState::Normal;d.confidence=s.synCount>0?Confidence::High:Confidence::Medium;
            d.conclusion=s.synCount>0
                ? QStringLiteral("TCP连接已建立：%1；三次握手完成，当前抓包窗口未观察到业务Payload").arg(flow)
                : QStringLiteral("TCP连接已建立：%1；已观察到 SYN/ACK→ACK，当前窗口未包含初始 SYN").arg(flow);
            d.evidence<<QStringLiteral("%1 | %2").arg(flow,s.synCount>0?QStringLiteral("SYN → SYN/ACK → ACK"):QStringLiteral("SYN/ACK → ACK"));
        }
        return d;
    }

    if(anyPayload){
        if(bothPayload){
            d.state=LayerState::Normal;d.confidence=Confidence::Medium;
            d.conclusion=QStringLiteral("TCP会话正在传输：%1，已观察到双向业务数据；当前抓包窗口未包含握手过程").arg(flow);
            d.evidence<<QStringLiteral("端点A载荷 %1 包/%2 bytes；端点B载荷 %3 包/%4 bytes")
                            .arg(s.payloadPacketsFromInitiator).arg(s.payloadBytesFromInitiator)
                            .arg(s.payloadPacketsFromResponder).arg(s.payloadBytesFromResponder);
        }else{
            d.state=LayerState::Warning;d.confidence=Confidence::Low;
            const QString dataSide=s.payloadPacketsFromInitiator>0?initiator:responder;
            d.conclusion=QStringLiteral("TCP会话仅观察到单向业务数据：%1；抓包窗口未包含握手，暂不能确认另一方向是否正常").arg(dataSide);
            d.evidence<<QStringLiteral("%1 | 仅见单向Payload").arg(flow);
            d.suggestions<<QStringLiteral("延长抓包时间，确认对端是否有ACK或业务应答");
        }
        return d;
    }

    d.state=LayerState::Unknown;d.confidence=Confidence::Low;
    d.conclusion=QStringLiteral("TCP会话证据不足：%1").arg(flow);
    return d;
}

LayerDiagnosis diagnoseSessions(const ChannelEvidence& e)
{
    LayerDiagnosis out;
    out.layer=QStringLiteral("TCP_SESSIONS");
    if(e.tcpSessions.isEmpty()){out.state=LayerState::NotTested;out.confidence=Confidence::Low;return out;}

    // Diagnose the current/main business session instead of letting an old failed attempt
    // permanently dominate the result. Priority is lexicographic: payload > established > newest.
    const int mainIndex=mainSessionIndex(e.tcpSessions);
    const LayerDiagnosis main=diagnoseSession(e.tcpSessions.at(mainIndex));
    out.state=main.state;out.confidence=main.confidence;out.conclusion=main.conclusion;out.evidence=main.evidence;out.suggestions=main.suggestions;

    int historicalWarnings=0,historicalErrors=0;
    for(int i=0;i<e.tcpSessions.size();++i){
        if(i==mainIndex)continue;
        const LayerDiagnosis d=diagnoseSession(e.tcpSessions.at(i));
        if(d.state==LayerState::Error)++historicalErrors;else if(d.state==LayerState::Warning)++historicalWarnings;
    }
    if(historicalErrors||historicalWarnings){
        out.evidence<<QStringLiteral("历史连接异常：%1个错误会话，%2个关注会话；当前结论以主业务会话为准").arg(historicalErrors).arg(historicalWarnings);
        if(out.state==LayerState::Normal)out.conclusion+=QStringLiteral("；当前会话正常，但诊断窗口内存在历史连接异常");
    }
    return out;
}
}

ChannelAnalyzer::ChannelAnalyzer(ChannelCriteria criteria):m_criteria(criteria){}

QString ChannelAnalyzer::endpoint(const QString& ip,quint16 port){
    return ep(ip,port);
}

QString ChannelAnalyzer::normalizedFlowKey(const ParsedPacket& p){
    const QString a=endpoint(p.sourceIp,p.sourcePort);
    const QString b=endpoint(p.destinationIp,p.destinationPort);
    return a<b ? a+QStringLiteral("|")+b : b+QStringLiteral("|")+a;
}

bool ChannelAnalyzer::matches(const ParsedPacket& p) const{
    if(!p.valid) return false;
    if(!m_criteria.peerIp.isEmpty() && p.sourceIp!=m_criteria.peerIp && p.destinationIp!=m_criteria.peerIp) return false;
    if(m_criteria.requirePeerPort){
        if(p.protocol!=QStringLiteral("TCP")) return p.protocol==QStringLiteral("ICMP");
        if(m_criteria.peerPort==0) return false;
        if(p.sourcePort!=m_criteria.peerPort && p.destinationPort!=m_criteria.peerPort) return false;
    }
    return true;
}

void ChannelAnalyzer::refreshSessions()
{
    m_evidence.tcpSessions=m_sessions.values();
    std::sort(m_evidence.tcpSessions.begin(),m_evidence.tcpSessions.end(),[](const TcpSessionEvidence& a,const TcpSessionEvidence& b){
        const QString ak=ep(a.initiatorIp,a.initiatorPort)+QStringLiteral("|")+ep(a.responderIp,a.responderPort);
        const QString bk=ep(b.initiatorIp,b.initiatorPort)+QStringLiteral("|")+ep(b.responderIp,b.responderPort);
        return ak<bk;
    });
}

void ChannelAnalyzer::consume(const ParsedPacket& p){
    if(!matches(p)) return;
    ++m_evidence.packets;

    if(p.protocol==QStringLiteral("ICMP")){
        if(p.ipTotalLength==140){
            ++m_evidence.icmp140;
            if(!m_criteria.peerIp.isEmpty() && p.sourceIp==m_criteria.peerIp) ++m_evidence.icmp140FromPeer;
        }
        return;
    }
    if(p.protocol!=QStringLiteral("TCP")) return;

    const bool syn=(p.tcpFlags&0x02)!=0;
    const bool ack=(p.tcpFlags&0x10)!=0;
    const bool psh=(p.tcpFlags&0x08)!=0;
    const QString key=normalizedFlowKey(p);
    const QString src=endpoint(p.sourceIp,p.sourcePort);
    const QString dst=endpoint(p.destinationIp,p.destinationPort);

    auto it=m_sessions.find(key);
    if(it==m_sessions.end()){
        TcpSessionEvidence session;
        if(syn && ack){
            // SYN/ACK itself identifies the responder even if the initial SYN was outside the capture window.
            session.initiatorIp=p.destinationIp;session.initiatorPort=p.destinationPort;
            session.responderIp=p.sourceIp;session.responderPort=p.sourcePort;
            session.initiatorKnown=true;
        }else{
            session.initiatorIp=p.sourceIp;session.initiatorPort=p.sourcePort;
            session.responderIp=p.destinationIp;session.responderPort=p.destinationPort;
            session.initiatorKnown=syn && !ack;
        }
        session.firstSeen=p.timestamp;session.lastSeen=p.timestamp;
        it=m_sessions.insert(key,session);
    }
    if(!it->firstSeen.isValid())it->firstSeen=p.timestamp;
    if(p.timestamp.isValid())it->lastSeen=p.timestamp;

    const bool fromInitiator=src==endpoint(it->initiatorIp,it->initiatorPort);
    const bool fromResponder=src==endpoint(it->responderIp,it->responderPort);

    if(syn && !ack){
        ++m_evidence.syn;
        if(!m_criteria.peerIp.isEmpty()){
            if(p.sourceIp==m_criteria.peerIp) ++m_evidence.synFromPeer;
            if(p.destinationIp==m_criteria.peerIp) ++m_evidence.synToPeer;
        }
        if(fromInitiator){
            it->initiatorKnown=true;
            ++it->synCount;
        }
    }else if(syn && ack){
        ++m_evidence.synAck;
        if(fromResponder)++it->synAckCount;
    }else if(ack){
        ++m_evidence.ack;
        if(fromInitiator){
            ++it->ackFromInitiator;
            if(it->synAckCount>0){it->handshakeComplete=true;m_evidence.handshakeComplete=true;}
        }
    }
    if(psh && ack) ++m_evidence.pshAck;
    if(p.tcpFlags&0x04){
        ++m_evidence.rst;
        if(it->firstRstIp.isEmpty()){it->firstRstIp=p.sourceIp;it->firstRstPort=p.sourcePort;it->firstRstTime=p.timestamp;}
        if(fromInitiator)++it->rstFromInitiator;else if(fromResponder)++it->rstFromResponder;
    }
    if(p.tcpFlags&0x01){
        ++m_evidence.fin;
        if(it->firstFinIp.isEmpty()){it->firstFinIp=p.sourceIp;it->firstFinPort=p.sourcePort;it->firstFinTime=p.timestamp;}
        if(fromInitiator)++it->finFromInitiator;else if(fromResponder)++it->finFromResponder;
    }
    if(p.tcpPayloadLength>0){
        if(!it->firstPayloadTime.isValid())it->firstPayloadTime=p.timestamp;
        if(p.timestamp.isValid())it->lastPayloadTime=p.timestamp;
        ++m_evidence.payloadPackets;
        m_evidence.payloadBytes+=p.tcpPayloadLength;
        if(fromInitiator){++it->payloadPacketsFromInitiator;it->payloadBytesFromInitiator+=p.tcpPayloadLength;}
        else if(fromResponder){++it->payloadPacketsFromResponder;it->payloadBytesFromResponder+=p.tcpPayloadLength;}
    }
    refreshSessions();
}

void ChannelAnalyzer::reset(){
    m_evidence=ChannelEvidence{};
    m_sessions.clear();
}

QString ChannelAnalyzer::tcpSessionReport(const ChannelEvidence& e,const QString& title)
{
    QString out;
    if(!title.isEmpty())out+=QStringLiteral("【%1】\n").arg(title);
    if(e.tcpSessions.isEmpty()){
        out+=QStringLiteral("当前抓包窗口未形成可识别的 TCP 会话。\n");
        return out;
    }
    int index=0;
    const int mainIndex=mainSessionIndex(e.tcpSessions);
    for(int sessionIndex=0;sessionIndex<e.tcpSessions.size();++sessionIndex){
        const TcpSessionEvidence& s=e.tcpSessions.at(sessionIndex);
        const LayerDiagnosis d=diagnoseSession(s);
        const QString role=sessionIndex==mainIndex?QStringLiteral("【主业务会话】 "):QStringLiteral("【历史/其他会话】 ");
        out+=s.initiatorKnown
            ? QStringLiteral("%1. %2%3:%4 → %5:%6\n").arg(++index).arg(role).arg(s.initiatorIp).arg(s.initiatorPort).arg(s.responderIp).arg(s.responderPort)
            : QStringLiteral("%1. %2%3:%4 ↔ %5:%6（抓包窗口未包含建链起点）\n").arg(++index).arg(role).arg(s.initiatorIp).arg(s.initiatorPort).arg(s.responderIp).arg(s.responderPort);
        out+=QStringLiteral("   状态：%1\n").arg(d.conclusion);
        out+=QStringLiteral("   SYN=%1  SYN/ACK=%2  RST=%3  FIN=%4\n")
                 .arg(s.synCount).arg(s.synAckCount)
                 .arg(s.rstFromInitiator+s.rstFromResponder).arg(s.finFromInitiator+s.finFromResponder);
        out+=(s.initiatorKnown
            ? QStringLiteral("   Payload：发起方 %1包/%2 bytes，应答方 %3包/%4 bytes\n")
            : QStringLiteral("   Payload：端点A %1包/%2 bytes，端点B %3包/%4 bytes\n"))
                 .arg(s.payloadPacketsFromInitiator).arg(s.payloadBytesFromInitiator)
                 .arg(s.payloadPacketsFromResponder).arg(s.payloadBytesFromResponder);
        for(const QString& ev:d.evidence)out+=QStringLiteral("   证据：%1\n").arg(ev);
        out+=QLatin1Char('\n');
    }
    return out;
}

LayerDiagnosis ChannelAnalyzer::diagnoseMaster(const PingResult& ping,const ChannelEvidence& e){
    LayerDiagnosis d; d.layer=QStringLiteral("MASTER_CHANNEL");
    const LayerDiagnosis tcp=diagnoseSessions(e);
    if(tcp.state==LayerState::Error || tcp.state==LayerState::Warning){
        d.state=tcp.state;d.confidence=tcp.confidence;d.conclusion=tcp.conclusion;
        d.evidence=tcp.evidence;d.suggestions=tcp.suggestions;
        if(e.icmp140FromPeer>0 && e.synFromPeer>0)
            d.evidence.prepend(QStringLiteral("主站→设备方向已到达：观察到140字节ICMP和TCP SYN；但TCP会话本身仍未完整建立"));
        if(ping.validOutput&&!ping.reachable && e.handshakeComplete)
            d.evidence.prepend(QStringLiteral("ICMP Ping未应答，但TCP证据优先：已观察到TCP建链/会话"));
        return d;
    }
    if(tcp.state==LayerState::Normal){
        d.state=LayerState::Normal;d.confidence=tcp.confidence;d.conclusion=tcp.conclusion;
        d.evidence=tcp.evidence;
        if(ping.validOutput&&!ping.reachable)
            d.evidence.prepend(QStringLiteral("主站未响应ICMP Ping，但TCP连接证据表明业务链路可用"));
        if(e.icmp140FromPeer>0)d.evidence<<QStringLiteral("主站→设备 140字节ICMP: %1").arg(e.icmp140FromPeer);
        return d;
    }
    if(e.icmp140FromPeer>0 && e.synFromPeer>0){
        d.state=LayerState::Normal;d.confidence=Confidence::High;
        d.conclusion=QStringLiteral("主站通道正常：已观察到主站发来的140字节ICMP和TCP SYN");
        d.evidence<<QStringLiteral("主站→设备 140字节ICMP: %1").arg(e.icmp140FromPeer)
                  <<QStringLiteral("主站→设备 TCP SYN: %1").arg(e.synFromPeer);
        return d;
    }
    if(ping.validOutput && ping.reachable){
        d.state=LayerState::Warning;d.confidence=Confidence::Medium;
        d.conclusion=QStringLiteral("主站IP可达，但当前抓包窗口尚不足以证明TCP业务链路正常");
        d.evidence<<ping.evidence;
        return d;
    }
    if(ping.validOutput && !ping.reachable && e.packets==0){
        if(explicitPingReachabilityFailure(ping)){
            d.state=LayerState::Error;d.confidence=Confidence::High;
            d.conclusion=ping.failureKind==PingFailureKind::NetworkUnreachable
                ? QStringLiteral("主站IP层不可达：路由器当前没有到主站的可用路由")
                : ping.failureKind==PingFailureKind::DestinationHostUnreachable
                    ? QStringLiteral("主站IP层不可达：已收到 Destination Host Unreachable")
                    : QStringLiteral("主站地址不可用：Ping命令报告目标地址解析失败");
            d.evidence<<ping.evidence;
            d.suggestions<<QStringLiteral("优先检查WAN路由、策略路由、网关/回程和ACL，再验证主站业务端口TCP");
            return d;
        }
        d.state=LayerState::Unknown;d.confidence=Confidence::Low;
        d.conclusion=QStringLiteral("主站未返回ICMP Echo Reply，主站可能禁Ping；当前又没有TCP证据，不能判定主站不可达");
        d.evidence<<ping.evidence;
        d.suggestions<<QStringLiteral("以主站业务端口TCP为主要依据：继续抓取SYN/SYN-ACK/RST和业务数据，不把Ping无应答单独作为故障结论");
        return d;
    }
    d.state=LayerState::Unknown;d.confidence=Confidence::Low;
    d.conclusion=QStringLiteral("主站通道证据不足");
    return d;
}

LayerDiagnosis ChannelAnalyzer::diagnoseTerminalEthernet(const PingResult& ping,const ChannelEvidence& e){
    LayerDiagnosis d; d.layer=QStringLiteral("TERMINAL_ETHERNET");
    const LayerDiagnosis tcp=diagnoseSessions(e);
    if(tcp.state!=LayerState::NotTested){
        d.state=tcp.state;d.confidence=tcp.confidence;d.conclusion=tcp.conclusion;
        d.evidence=tcp.evidence;d.suggestions=tcp.suggestions;
        if(ping.validOutput&&!ping.reachable && tcp.state==LayerState::Normal)
            d.evidence.prepend(QStringLiteral("终端未响应ICMP Ping，但TCP连接证据表明终端业务链路可用"));
        return d;
    }
    if(ping.validOutput && !ping.reachable && e.packets==0){
        d.state=LayerState::Warning;d.confidence=Confidence::Low;
        d.conclusion=QStringLiteral("终端未响应ICMP Ping，且当前尚未观察到业务TCP；ICMP可能被禁用，暂不能仅凭Ping判定终端不可达");
        d.evidence<<ping.evidence;
        d.suggestions<<QStringLiteral("继续在与终端同网段的 LAN 接口（br0/br0:1）抓取终端IP及业务端口TCP，再结合SYN/SYN-ACK/RST和业务数据判断")
                     <<QStringLiteral("若持续无TCP证据，再检查终端IP、网段、网线、LAN口和终端网卡");
        return d;
    }
    if(ping.validOutput && ping.reachable){
        d.state=LayerState::Normal;d.confidence=Confidence::Medium;
        d.conclusion=QStringLiteral("路由器可以Ping通终端，IP层可达；尚未观察到足够TCP业务流量");
        d.evidence<<ping.evidence;
        return d;
    }
    if(e.packets>0){
        d.state=LayerState::Warning;d.confidence=Confidence::Medium;
        d.conclusion=QStringLiteral("终端LAN接口能观察到终端流量，但当前证据不足以确认TCP会话状态");
        return d;
    }
    d.state=LayerState::Unknown;d.confidence=Confidence::Low;
    d.conclusion=QStringLiteral("终端网口通道尚未测试或证据不足");
    return d;
}


QList<TcpSessionEvidence> ChannelAnalyzer::actualPeerSessions(const ChannelEvidence& evidence,EndpointRole role,quint16 businessPort)
{
    Q_UNUSED(role);
    QList<TcpSessionEvidence> out;
    for(const TcpSessionEvidence& session:evidence.tcpSessions){
        if(businessPort>0 && session.initiatorPort!=businessPort && session.responderPort!=businessPort)continue;
        out<<session;
    }
    std::sort(out.begin(),out.end(),[](const TcpSessionEvidence& a,const TcpSessionEvidence& b){return betterMainSession(a,b);});
    return out;
}

QStringList ChannelAnalyzer::actualPeerIps(const ChannelEvidence& evidence,EndpointRole role,quint16 businessPort)
{
    QStringList ips;
    auto add=[&ips](const QString& ip){if(!ip.isEmpty()&&!ips.contains(ip))ips<<ip;};
    for(const TcpSessionEvidence& session:actualPeerSessions(evidence,role,businessPort)){
        QString candidate;
        if(role==EndpointRole::Client){
            if(businessPort>0&&session.responderPort==businessPort&&session.initiatorPort!=businessPort)candidate=session.initiatorIp;
            else if(businessPort>0&&session.initiatorPort==businessPort&&session.responderPort!=businessPort)candidate=session.responderIp;
            else candidate=session.initiatorIp;
        }else{
            if(businessPort>0&&session.initiatorPort==businessPort)candidate=session.initiatorIp;
            else if(businessPort>0&&session.responderPort==businessPort)candidate=session.responderIp;
            else candidate=session.responderIp;
        }
        add(candidate);
    }
    return ips;
}

bool ChannelAnalyzer::packetFromActualPeer(const ParsedPacket& packet,const QList<TcpSessionEvidence>& sessions,EndpointRole role,quint16 businessPort)
{
    if(!packet.valid||packet.protocol!=QStringLiteral("TCP")||packet.tcpPayloadLength==0)return false;
    if(businessPort>0&&packet.sourcePort!=businessPort&&packet.destinationPort!=businessPort)return false;
    for(const TcpSessionEvidence& s:sessions){
        const bool forward=packet.sourceIp==s.initiatorIp&&packet.sourcePort==s.initiatorPort&&packet.destinationIp==s.responderIp&&packet.destinationPort==s.responderPort;
        const bool reverse=packet.sourceIp==s.responderIp&&packet.sourcePort==s.responderPort&&packet.destinationIp==s.initiatorIp&&packet.destinationPort==s.initiatorPort;
        if(!forward&&!reverse)continue;
        QString masterIp;quint16 masterPort=0;
        if(role==EndpointRole::Client){
            if(businessPort>0&&s.responderPort==businessPort&&s.initiatorPort!=businessPort){masterIp=s.initiatorIp;masterPort=s.initiatorPort;}
            else if(businessPort>0&&s.initiatorPort==businessPort&&s.responderPort!=businessPort){masterIp=s.responderIp;masterPort=s.responderPort;}
            else {masterIp=s.initiatorIp;masterPort=s.initiatorPort;}
        }else{
            if(businessPort>0&&s.initiatorPort==businessPort){masterIp=s.initiatorIp;masterPort=s.initiatorPort;}
            else if(businessPort>0&&s.responderPort==businessPort){masterIp=s.responderIp;masterPort=s.responderPort;}
            else {masterIp=s.responderIp;masterPort=s.responderPort;}
        }
        return packet.sourceIp==masterIp&&packet.sourcePort==masterPort;
    }
    return false;
}

bool ChannelAnalyzer::packetFromActualPeer(const ParsedPacket& packet,const QStringList& actualPeerIps,EndpointRole role,quint16 businessPort)
{
    if(!packet.valid || packet.protocol!=QStringLiteral("TCP") || packet.tcpPayloadLength==0)return false;
    if(businessPort>0 && packet.sourcePort!=businessPort && packet.destinationPort!=businessPort)return false;
    if(!actualPeerIps.isEmpty())return actualPeerIps.contains(packet.sourceIp);
    if(role==EndpointRole::Client)return businessPort>0 && packet.destinationPort==businessPort && packet.sourcePort!=businessPort;
    return businessPort>0 && packet.sourcePort==businessPort;
}

LayerDiagnosis ChannelAnalyzer::diagnoseMaster(const PingResult& ping,const ChannelEvidence& evidence,EndpointRole role,int expectedSeconds)
{
    if(role==EndpointRole::Client && evidence.tcpSessions.isEmpty() && evidence.syn==0 && evidence.payloadPackets==0){
        LayerDiagnosis d;
        d.layer=QStringLiteral("MASTER_CHANNEL");
        d.state=LayerState::Warning;
        d.confidence=Confidence::Medium;
        d.conclusion=QStringLiteral("主站客户端在%1秒诊断窗口内未观察到发起TCP连接").arg(qMax(1,expectedSeconds));
        if(ping.validOutput&&!ping.reachable)d.evidence<<QStringLiteral("配置主站IP的ICMP未应答仅作辅助证据；主站可能禁Ping");
        d.suggestions<<QStringLiteral("检查主站客户端程序是否运行、连接目标地址/端口是否正确，以及主站侧网络/NAT/防火墙策略");
        return d;
    }
    LayerDiagnosis d=diagnoseMaster(ping,evidence);
    if(role==EndpointRole::Client && !evidence.tcpSessions.isEmpty())
        d.evidence.prepend(QStringLiteral("角色判断：主站=客户端，应由主站侧主动发起TCP连接"));
    else if(role==EndpointRole::Server && !evidence.tcpSessions.isEmpty())
        d.evidence.prepend(QStringLiteral("角色判断：主站=服务端，应由现场侧主动连接主站服务端"));
    return d;
}

LayerDiagnosis ChannelAnalyzer::diagnoseTerminalEthernet(const PingResult& ping,const ChannelEvidence& evidence,EndpointRole role,int expectedSeconds)
{
    const bool noTcp=evidence.tcpSessions.isEmpty() && evidence.syn==0 && evidence.payloadPackets==0;
    if(noTcp){
        LayerDiagnosis d;
        d.layer=QStringLiteral("TERMINAL_ETHERNET");
        d.state=LayerState::Warning;
        d.confidence=Confidence::Low;
        if(role==EndpointRole::Client){
            d.conclusion=QStringLiteral("终端客户端在%1秒诊断窗口内未观察到主动发起TCP连接").arg(qMax(1,expectedSeconds));
            d.suggestions<<QStringLiteral("检查终端客户端程序、目标主站地址/端口、终端网卡和网线");
        }else{
            d.conclusion=QStringLiteral("终端服务端在%1秒诊断窗口内未观察到业务TCP连接请求").arg(qMax(1,expectedSeconds));
            d.suggestions<<QStringLiteral("终端默认为服务端；确认主站客户端是否已经发起连接，并检查终端监听端口和LAN侧网络");
        }
        if(ping.validOutput&&!ping.reachable)d.evidence<<QStringLiteral("终端ICMP未应答，仍不能单独据此判定终端离线");
        return d;
    }
    LayerDiagnosis d=diagnoseTerminalEthernet(ping,evidence);
    d.evidence.prepend(role==EndpointRole::Client
        ?QStringLiteral("角色判断：终端=客户端，应由终端主动发起TCP连接")
        :QStringLiteral("角色判断：终端=服务端，默认等待主站/上游连接"));
    return d;
}
