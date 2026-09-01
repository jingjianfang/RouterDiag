#include <QtTest>
#include <QFile>
#include "protocol/GridSecurityAnalyzer.h"

class TestGridSecurityAnalyzer : public QObject {
    Q_OBJECT
private slots:
void parsesDirectionAndCommand(){
    const auto f=GridSecurityAnalyzer::parseHexLogLine(
        QString::fromUtf8("主站→模块: EB 00 0D EB 00 80 20 00 08 61 F9 3F 93 14 37 22 56 97 D7"));
    QVERIFY(f.valid);
    QCOMPARE(f.direction,GridDirection::MasterToModule);
    QCOMPARE(f.control,quint8(0x80));
    QCOMPARE(f.command,quint8(0x20));
}
void normalReferenceSequencesAreDirectionAware(){
    QFile f(QFINDTESTDATA("fixtures/grid_security_normal.txt"));
    QVERIFY(f.open(QIODevice::ReadOnly));
    GridSecurityAnalyzer a;
    const auto lines=QString::fromUtf8(f.readAll()).split('\n',Qt::SkipEmptyParts);
    for(const auto& line: lines) a.consume(GridSecurityAnalyzer::parseHexLogLine(line));
    const auto e=a.evidence();
    QVERIFY(e.auth8020To8023Complete);
    QVERIFY(e.sequence5051Seen);
    QVERIFY(e.sequence5253Seen);
    QVERIFY(e.sequence5455Seen);
    QVERIFY(e.sequence6061Seen);
    QVERIFY(!e.repeated56Without5051);
}
void repeated56IsBaselineDeviationOnlyAfterThreshold(){
    QFile f(QFINDTESTDATA("fixtures/grid_security_repeated_56.txt"));
    QVERIFY(f.open(QIODevice::ReadOnly));
    GridSecurityAnalyzer a;
    const auto lines=QString::fromUtf8(f.readAll()).split('\n',Qt::SkipEmptyParts);
    for(const auto& line: lines) a.consume(GridSecurityAnalyzer::parseHexLogLine(line));
    const auto e=a.evidence();
    QCOMPARE(e.commandCounts.value(0x56),quint64(6));
    QVERIFY(e.repeated56Without5051);
    QVERIFY(e.evidence.join('\n').contains(QString::fromUtf8("正常样本基线")));
}
void invalidLengthIsRejected(){
    const auto f=GridSecurityAnalyzer::parseHexLogLine(
        QString::fromUtf8("主站→模块: EB 00 06 EB 00 01 56 00 00 57 D7"));
    QVERIFY(!f.valid);
    QVERIFY(f.error.contains("length",Qt::CaseInsensitive));
}
};
QTEST_MAIN(TestGridSecurityAnalyzer)
#include "test_gridsecurityanalyzer.moc"
