#include "PacketAnalyzer.h"
#include <algorithm>
#include <QCryptographicHash>
QString PacketAnalyzer::flowKey(const ParsedPacket& p) const{return QStringLiteral("%1:%2>%3:%4").arg(p.sourceIp).arg(p.sourcePort).arg(p.destinationIp).arg(p.destinationPort);}
QString PacketAnalyzer::conversationKey(const ParsedPacket& p) const{QString a=QStringLiteral("%1:%2").arg(p.sourceIp).arg(p.sourcePort),b=QStringLiteral("%1:%2").arg(p.destinationIp).arg(p.destinationPort);return a<b?a+" <-> "+b:b+" <-> "+a;}
void PacketAnalyzer::consume(const ParsedPacket& p){if(!p.valid)return;m_stats.totalPackets++;m_stats.totalBytes+=p.capturedLength;m_conversations[conversationKey(p)]++;
 if(p.protocol=="TCP"){m_stats.tcpPackets++;if(p.tcpFlags&0x02){m_stats.tcpSyn++;if(!(p.tcpFlags&0x10))m_pendingSyn.insert(flowKey(p));else{QString rev=QStringLiteral("%1:%2>%3:%4").arg(p.destinationIp).arg(p.destinationPort).arg(p.sourceIp).arg(p.sourcePort);m_pendingSyn.remove(rev);}}
 if(p.tcpFlags&0x04){m_stats.tcpRst++;QString rev=QStringLiteral("%1:%2>%3:%4").arg(p.destinationIp).arg(p.destinationPort).arg(p.sourceIp).arg(p.sourcePort);m_pendingSyn.remove(rev);m_pendingSyn.remove(flowKey(p));}
 if(p.tcpFlags&0x01)m_stats.tcpFin++;
 // Pure ACK packets commonly reuse the same sequence number and are not retransmissions.
 // Only count duplicate payload-bearing TCP segments with the same flow/SEQ/length/content hash.
 if(p.tcpPayloadLength>0){const QByteArray hash=QCryptographicHash::hash(p.payload,QCryptographicHash::Sha1).toHex();QString seq=flowKey(p)+QStringLiteral("#%1#%2#%3").arg(p.sequence).arg(p.tcpPayloadLength).arg(QString::fromLatin1(hash));if(m_tcpSequenceSeen.contains(seq))m_stats.suspectedRetransmissions++;else{m_tcpSequenceSeen.insert(seq);m_tcpSequenceOrder.enqueue(seq);constexpr int MaxRememberedSegments=100000;while(m_tcpSequenceOrder.size()>MaxRememberedSegments)m_tcpSequenceSeen.remove(m_tcpSequenceOrder.dequeue());}}
 } else if(p.protocol=="UDP")m_stats.udpPackets++;else if(p.protocol=="ICMP"){m_stats.icmpPackets++;if(p.icmpType==8)m_stats.icmpEchoRequests++;if(p.icmpType==0)m_stats.icmpEchoReplies++;}m_stats.synWithoutResponse=m_pendingSyn.size();}
QStringList PacketAnalyzer::topConversations(int limit) const{QList<QPair<QString,quint64>> v;for(auto i=m_conversations.cbegin();i!=m_conversations.cend();++i)v.append({i.key(),i.value()});std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});QStringList out;for(int i=0;i<qMin(limit,v.size());++i)out<<QStringLiteral("%1 (%2 packets)").arg(v[i].first).arg(v[i].second);return out;}
void PacketAnalyzer::reset(){m_stats=CaptureStats{};m_conversations.clear();m_tcpSequenceSeen.clear();m_tcpSequenceOrder.clear();m_pendingSyn.clear();}
