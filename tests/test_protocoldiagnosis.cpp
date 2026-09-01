#include <QtTest>
#include <QFile>
#include "protocol/ProtocolDiagnosis.h"

class TestProtocolDiagnosis : public QObject {
    Q_OBJECT
private slots:
    void classifiesVisibleIec104(){
        const QByteArray payload=QByteArray::fromHex("680407000000");
        const ProtocolEvidence e=ProtocolDiagnosis::analyzeTcpPayload(payload);
        QCOMPARE(e.protocol,BusinessProtocol::Iec104);
        QCOMPARE(e.iec104Frames,quint64(1));
        QVERIFY(e.iec104StartDtActSeen);
        const auto layers=ProtocolDiagnosis::buildLayers(e);
        QCOMPARE(layers.size(),1);
        QCOMPARE(layers[0].layer,QString("BUSINESS_DATA"));
        QVERIFY(layers[0].conclusion.contains("IEC104"));
    }

    void classifiesVisibleIec101(){
        const QByteArray payload=QByteArray::fromHex("1049014A16");
        const ProtocolEvidence e=ProtocolDiagnosis::analyzeSerialBytes(payload);
        QCOMPARE(e.protocol,BusinessProtocol::Iec101);
        QCOMPARE(e.iec101Frames,quint64(1));
        QVERIFY(e.evidence.join('\n').contains("IEC101"));
    }

    void gridEnvelopeDoesNotPretendToDecryptBusinessProtocol(){
        const QByteArray payload=QByteArray::fromHex("EB000DEB008020000861F93F931437225697D7");
        const ProtocolEvidence e=ProtocolDiagnosis::analyzeTcpPayload(payload);
        QCOMPARE(e.gridFrames,quint64(1));
        QCOMPARE(e.protocol,BusinessProtocol::Unknown);
        QVERIFY(!e.encryptedContentVisible);
        const auto layers=ProtocolDiagnosis::buildLayers(e);
        QCOMPARE(layers.size(),1);
        QCOMPARE(layers[0].layer,QString("BUSINESS_DATA"));
        QVERIFY(layers[0].conclusion.contains(QString::fromUtf8("不可确认")) ||
                layers[0].conclusion.contains(QString::fromUtf8("不可见")));
    }

    void repeated56IsRenderedAsBaselineDeviationNotIllegalCommand(){
        QFile f(QFINDTESTDATA("fixtures/grid_security_repeated_56.txt"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        const ProtocolEvidence e=ProtocolDiagnosis::analyzeLogText(QString::fromUtf8(f.readAll()));
        QVERIFY(e.gridRepeated56Without5051);
        const auto layers=ProtocolDiagnosis::buildLayers(e);
        QCOMPARE(layers[0].state,LayerState::Warning);
        const QString text=layers[0].conclusion+"\n"+layers[0].evidence.join('\n');
        QVERIFY(text.contains(QString::fromUtf8("正常样本基线")));
        QVERIFY(!text.contains(QString::fromUtf8("非法命令")));
    }

    void mergeAccumulatesSameProtocolEvidence(){
        ProtocolEvidence total;
        ProtocolDiagnosis::merge(total,ProtocolDiagnosis::analyzeTcpPayload(QByteArray::fromHex("680407000000")));
        ProtocolDiagnosis::merge(total,ProtocolDiagnosis::analyzeTcpPayload(QByteArray::fromHex("68040B000000")));
        QCOMPARE(total.protocol,BusinessProtocol::Iec104);
        QCOMPARE(total.iec104Frames,quint64(2));
        QVERIFY(total.iec104StartDtActSeen);
        QVERIFY(total.iec104StartDtConSeen);
        QVERIFY(ProtocolDiagnosis::buildLayers(total)[0].conclusion.contains("STARTDT"));
        QVERIFY(ProtocolDiagnosis::buildLayers(total)[0].conclusion.contains(QString::fromUtf8("业务通信正常")));
    }
};

QTEST_MAIN(TestProtocolDiagnosis)
#include "test_protocoldiagnosis.moc"
