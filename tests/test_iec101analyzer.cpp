#include <QtTest>
#include "protocol/Iec101Analyzer.h"

class TestIec101Analyzer : public QObject {
    Q_OBJECT
private slots:
void parsesFixedFrame(){
    // checksum = 0x49 + 0x01 = 0x4A
    const auto frames=Iec101Analyzer::parseStream(QByteArray::fromHex("1049014a16"));
    QCOMPARE(frames.size(),1);
    QVERIFY(frames[0].valid);
    QCOMPARE(frames[0].kind,Iec101FrameKind::Fixed);
    QCOMPARE(frames[0].control,quint8(0x49));
}
void parsesVariableFrameAndTypeId(){
    // L=7: C=53, A=01, ASDU=64 01 06 00 01; checksum C0.
    const auto frames=Iec101Analyzer::parseStream(QByteArray::fromHex("6807076853016401060001c016"));
    QCOMPARE(frames.size(),1);
    QVERIFY(frames[0].valid);
    QCOMPARE(frames[0].kind,Iec101FrameKind::Variable);
    QCOMPARE(frames[0].control,quint8(0x53));
    QCOMPARE(frames[0].typeId,100);
}
void rejectsBadChecksum(){
    const auto frames=Iec101Analyzer::parseStream(QByteArray::fromHex("1049010016"));
    QCOMPARE(frames.size(),1);
    QVERIFY(!frames[0].valid);
    QVERIFY(frames[0].error.contains("checksum",Qt::CaseInsensitive));
}
void rejectsMismatchedVariableLengths(){
    const auto frames=Iec101Analyzer::parseStream(QByteArray::fromHex("6807086853016401060001c016"));
    QCOMPARE(frames.size(),1);
    QVERIFY(!frames[0].valid);
    QVERIFY(frames[0].error.contains("length",Qt::CaseInsensitive));
}
};
QTEST_MAIN(TestIec101Analyzer)
#include "test_iec101analyzer.moc"
