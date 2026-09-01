#include <QtTest>
#include "capture/PacketAnalyzer.h"
class TestPacketAnalyzer: public QObject {
    Q_OBJECT
private slots:
void counters(){ PacketAnalyzer a; ParsedPacket p; p.valid=true;p.protocol="ICMP";p.capturedLength=64;p.icmpType=8;a.consume(p); auto s=a.stats(); QCOMPARE(s.totalPackets,quint64(1)); QCOMPARE(s.icmpEchoRequests,quint64(1)); }
void retransmission(){ PacketAnalyzer a; ParsedPacket p; p.valid=true;p.protocol="TCP";p.sourceIp="1.1.1.1";p.destinationIp="2.2.2.2";p.sourcePort=1;p.destinationPort=2;p.sequence=100;p.capturedLength=60;p.tcpPayloadLength=3;p.payload="abc";a.consume(p);a.consume(p); QCOMPARE(a.stats().suspectedRetransmissions,quint64(1)); }
void repeatedPureAckIsNotRetransmission(){ PacketAnalyzer a;ParsedPacket p;p.valid=true;p.protocol="TCP";p.sourceIp="1.1.1.1";p.destinationIp="2.2.2.2";p.sourcePort=1;p.destinationPort=2;p.sequence=100;p.tcpFlags=0x10;a.consume(p);a.consume(p);QCOMPARE(a.stats().suspectedRetransmissions,quint64(0));}
void rstAnswersPendingSyn(){PacketAnalyzer a;ParsedPacket syn;syn.valid=true;syn.protocol="TCP";syn.sourceIp="1.1.1.1";syn.destinationIp="2.2.2.2";syn.sourcePort=111;syn.destinationPort=2404;syn.tcpFlags=0x02;a.consume(syn);QCOMPARE(a.stats().synWithoutResponse,quint64(1));ParsedPacket rst=syn;rst.sourceIp="2.2.2.2";rst.destinationIp="1.1.1.1";rst.sourcePort=2404;rst.destinationPort=111;rst.tcpFlags=0x14;a.consume(rst);QCOMPARE(a.stats().synWithoutResponse,quint64(0));}
};
QTEST_MAIN(TestPacketAnalyzer)
#include "test_packetanalyzer.moc"
