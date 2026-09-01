#include <QtTest>
#include "protocol/Iec104Analyzer.h"

class TestIec104Analyzer : public QObject {
    Q_OBJECT
private slots:
void parsesUFrames(){
    struct Case { const char* hex; Iec104UFunction fn; } cases[] = {
        {"680407000000", Iec104UFunction::StartDtAct},
        {"68040b000000", Iec104UFunction::StartDtCon},
        {"680443000000", Iec104UFunction::TestFrAct},
        {"680483000000", Iec104UFunction::TestFrCon}
    };
    for(const auto& c: cases){
        const auto frames=Iec104Analyzer::parseStream(QByteArray::fromHex(c.hex));
        QCOMPARE(frames.size(),1);
        QVERIFY(frames[0].valid);
        QCOMPARE(frames[0].kind,Iec104FrameKind::U);
        QCOMPARE(frames[0].uFunction,c.fn);
    }
}
void parsesIFrameAndBasicAsdu(){
    const auto frames=Iec104Analyzer::parseStream(QByteArray::fromHex("680a00000000640106000100"));
    QCOMPARE(frames.size(),1);
    const auto f=frames[0];
    QVERIFY(f.valid);
    QCOMPARE(f.kind,Iec104FrameKind::I);
    QCOMPARE(f.sendSequence,quint16(0));
    QCOMPARE(f.receiveSequence,quint16(0));
    QCOMPARE(f.typeId,100);
    QCOMPARE(f.cot,6);
    QCOMPARE(f.commonAddress,1);
}
void parsesSFrame(){
    const auto frames=Iec104Analyzer::parseStream(QByteArray::fromHex("680401000200"));
    QCOMPARE(frames.size(),1);
    QVERIFY(frames[0].valid);
    QCOMPARE(frames[0].kind,Iec104FrameKind::S);
    QCOMPARE(frames[0].receiveSequence,quint16(1));
}
void rejectsDeclaredLengthBeyondAvailableBytes(){
    const auto frames=Iec104Analyzer::parseStream(QByteArray::fromHex("680a00000000"));
    QCOMPARE(frames.size(),1);
    QVERIFY(!frames[0].valid);
    QVERIFY(frames[0].error.contains("length",Qt::CaseInsensitive));
}
void parsesConcatenatedApdus(){
    const auto frames=Iec104Analyzer::parseStream(QByteArray::fromHex("68040700000068040b000000"));
    QCOMPARE(frames.size(),2);
    QCOMPARE(frames[0].uFunction,Iec104UFunction::StartDtAct);
    QCOMPARE(frames[1].uFunction,Iec104UFunction::StartDtCon);
}
};
QTEST_MAIN(TestIec104Analyzer)
#include "test_iec104analyzer.moc"
