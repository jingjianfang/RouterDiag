#include <QtTest>
#include "diagnostic/DualCaptureCorrelator.h"

class TestDualCaptureCorrelator: public QObject {
    Q_OBJECT
private slots:
void correlatesAcrossNatBySeqPayloadAndTime(){
    DualCaptureCorrelator c;ParsedPacket lan;lan.valid=true;lan.protocol="TCP";lan.sequence=100;lan.tcpPayloadLength=4;lan.payload=QByteArray::fromHex("01020304");lan.timestamp=QDateTime::fromMSecsSinceEpoch(1000);lan.sourceIp="192.168.1.2";lan.destinationIp="10.0.0.1";lan.sourcePort=2404;lan.destinationPort=50000;
    ParsedPacket wan=lan;wan.timestamp=QDateTime::fromMSecsSinceEpoch(1003);wan.sourceIp="100.64.1.2";wan.destinationIp="203.0.113.1";wan.sourcePort=41000;wan.destinationPort=2404;
    c.consume(CaptureSide::TerminalLan,lan);c.consume(CaptureSide::Wan,wan);const auto s=c.summary();QCOMPARE(s.matchedPackets,quint64(1));QCOMPARE(s.terminalOnlyPackets,quint64(0));QCOMPARE(s.wanOnlyPackets,quint64(0));QVERIFY(s.averageForwardDelayMs>=3.0&&s.averageForwardDelayMs<4.0);
}
};
QTEST_MAIN(TestDualCaptureCorrelator)
#include "test_dualcapturecorrelator.moc"
