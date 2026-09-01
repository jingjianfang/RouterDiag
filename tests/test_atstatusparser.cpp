#include <QtTest>
#include "diagnostic/AtStatusParser.h"

class TestAtStatusParser: public QObject {
    Q_OBJECT
private slots:
void parsesSimpleStatus(){
    const auto r=AtStatusParser::parseRegistration(QStringLiteral("1"));
    QVERIFY(r.valid);QCOMPARE(r.status,1);QVERIFY(r.registered());QCOMPARE(r.mode,-1);
}
void parsesQueryExtendedStatus(){
    const auto r=AtStatusParser::parseRegistration(QStringLiteral("+CEREG: 2,1,\"1234\",\"56789ABC\",7"));
    QVERIFY(r.valid);QCOMPARE(r.mode,2);QCOMPARE(r.status,1);QCOMPARE(r.areaCode,QString("1234"));QCOMPARE(r.cellId,QString("56789ABC"));QCOMPARE(r.accessTechnology,7);QVERIFY(r.registered());
}
void parsesRejectedWithCause(){
    const auto r=AtStatusParser::parseRegistration(QStringLiteral("2,3,\"1234\",\"56789ABC\",7,0,15"));
    QVERIFY(r.valid);QCOMPARE(r.status,3);QCOMPARE(r.rejectType,0);QCOMPARE(r.rejectCause,15);QVERIFY(!r.registered());
}
void doesNotTreatQuotedTacAsQueryStatus(){
    const auto r=AtStatusParser::parseRegistration(QStringLiteral("+CEREG: 3,\"0001\",\"12345678\",7"));
    QVERIFY(r.valid);QCOMPARE(r.mode,-1);QCOMPARE(r.status,3);QCOMPARE(r.areaCode,QString("0001"));QCOMPARE(r.cellId,QString("12345678"));
    QVERIFY(r.fieldQuoted.size()>=3);QVERIFY(r.fieldQuoted.at(1));
}
void selectsRegistrationDomainByRat(){
    const auto lte=AtStatusParser::preferredRegistration(QStringLiteral("2,1,\"A\",\"B\",11"),QStringLiteral("2,3,\"A\",\"B\",7"),QStringLiteral("2,1"),QStringLiteral("2,1"),7);
    QVERIFY(lte.valid());QCOMPARE(lte.source,QString("CEREG"));QCOMPARE(lte.info.status,3);
    const auto nr=AtStatusParser::preferredRegistration(QStringLiteral("2,1,\"A\",\"B\",11"),QStringLiteral("2,3,\"A\",\"B\",7"),QString(),QString(),11);
    QVERIFY(nr.valid());QCOMPARE(nr.source,QString("C5GREG"));QCOMPARE(nr.info.status,1);
}
void parsesOperator(){
    const auto op=AtStatusParser::parseOperator(QStringLiteral("+COPS: 0,0,\"China Mobile\",7"));
    QVERIFY(op.valid);QCOMPARE(op.operatorName,QString("China Mobile"));QCOMPARE(op.accessTechnology,7);
}
void supportsExtendedRegistrationStates(){
    const auto limited=AtStatusParser::parseRegistration(QStringLiteral("+CEREG: 2,6,\"1234\",\"56789ABC\",7"));
    QVERIFY(limited.valid);QVERIFY(limited.limitedRegistration());QVERIFY(!limited.registered());
    QVERIFY(AtStatusParser::registrationStatusText(6).contains(QString::fromUtf8("数据业务受限")));
    const auto csfb=AtStatusParser::parseRegistration(QStringLiteral("+CEREG: 2,10,\"1234\",\"56789ABC\",7"));
    QVERIFY(csfb.valid);QVERIFY(csfb.registered());QVERIFY(csfb.roaming());
}
void cmeDescriptions(){QCOMPARE(AtStatusParser::cmeErrorText(10),QString("SIM未插入"));}
void rejectCauseDescriptions(){
    QCOMPARE(AtStatusParser::rejectCauseText(15),QString("当前跟踪区/位置区无合适小区"));
    QVERIFY(AtStatusParser::rejectCauseText(111).contains(QString("协议")));
}
};
QTEST_MAIN(TestAtStatusParser)
#include "test_atstatusparser.moc"
