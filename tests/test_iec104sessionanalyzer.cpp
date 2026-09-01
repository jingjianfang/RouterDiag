#include <QtTest>
#include "protocol/Iec104SessionAnalyzer.h"

class TestIec104SessionAnalyzer: public QObject {
    Q_OBJECT
private slots:
void detectsStartAndSequenceGap(){
    ReassembledTcpDirection a; a.sourceEndpoint="A:1";a.destinationEndpoint="B:2404";
    a.bytes=QByteArray::fromHex("680407000000680a00000000640106000100680a04000000640106000100"); // I N(S)=0 then N(S)=2
    ReassembledTcpDirection b; b.sourceEndpoint="B:2404";b.destinationEndpoint="A:1";b.bytes=QByteArray::fromHex("68040b000000680401000600");
    const auto s=Iec104SessionAnalyzer::analyze({a,b});QVERIFY(s.startDtActSeen);QVERIFY(s.startDtConSeen);QCOMPARE(s.sequenceGapCount,quint64(1));
}
void countsUnacknowledgedIFramesWhenNoReverseAckCaptured(){
    ReassembledTcpDirection a;a.sourceEndpoint="A:1";a.destinationEndpoint="B:2404";
    a.bytes=QByteArray::fromHex("680a00000000640106000100680a02000000640106000100680a04000000640106000100");
    const auto s=Iec104SessionAnalyzer::analyze({a});
    QCOMPARE(s.outstandingIFrames,quint64(3));
    QVERIFY(s.evidence.join('\n').contains(QString::fromUtf8("未观察到对端N(R)")));
}
void boundsOutstandingEstimateWhenCaptureStartsMidSession(){
    ReassembledTcpDirection a;a.sourceEndpoint="A:1";a.destinationEndpoint="B:2404";
    // Capture starts at N(S)=10/11, while the only reverse N(R) visible is stale (0).
    // The analyzer must not claim 12 outstanding frames when only two I-frames were observed.
    a.bytes=QByteArray::fromHex("680a14000000640106000100680a16000000640106000100");
    ReassembledTcpDirection b;b.sourceEndpoint="B:2404";b.destinationEndpoint="A:1";
    b.bytes=QByteArray::fromHex("680401000000");
    const auto s=Iec104SessionAnalyzer::analyze({a,b});
    QCOMPARE(s.outstandingIFrames,quint64(2));
}


};
QTEST_MAIN(TestIec104SessionAnalyzer)
#include "test_iec104sessionanalyzer.moc"
