#include <QtTest>
#include "diagnostic/NvramSnapshotParser.h"

namespace {
void appendRecord(QByteArray& bytes,const QByteArray& key,const QByteArray& value)
{
    QVERIFY(key.size()<=255);
    QVERIFY(value.size()<=65535);
    bytes.append(char(key.size()));
    bytes.append(key);
    const quint16 n=quint16(value.size());
    bytes.append(char(n&0xff));
    bytes.append(char((n>>8)&0xff));
    bytes.append(value);
}
}

class TestNvramSnapshotParser: public QObject {
    Q_OBJECT
private slots:
    void parsesNvramShowText(){
        const QByteArray text(
            "wan_proto=disabled\n"
            "wan_ipaddr=0.0.0.0\n"
            "bkup_wan_proto=4gdhcp1\n"
            "bkupwanup=1\n"
            "bkup_wan_ipaddr=10.20.30.40\n"
            "comm_wan_ipaddr=10.20.30.40\n"
            "comm_name=NRLCM-M2\n"
            "nvram_ver=3\n");
        const NvramSnapshot s=NvramSnapshotParser::parse(text);
        QVERIFY(s.valid);
        QCOMPARE(s.format,NvramSnapshotFormat::Text);
        QCOMPARE(s.value(QStringLiteral("bkup_wan_ipaddr")),QStringLiteral("10.20.30.40"));
        QVERIFY(s.recordCount>=8);
    }

    void parsesFourFaithBinary(){
        QByteArray bytes("FOUR-FAITH:");
        bytes.append(char(7));
        appendRecord(bytes,"wan_proto","4gdhcp");
        appendRecord(bytes,"wanup","1");
        appendRecord(bytes,"wan_ipaddr","10.10.10.2");
        appendRecord(bytes,"comm_name","L716-CN");
        appendRecord(bytes,"nvram_ver","3");
        const NvramSnapshot s=NvramSnapshotParser::parse(bytes);
        QVERIFY(s.valid);
        QCOMPARE(s.format,NvramSnapshotFormat::FourFaithBinary);
        QCOMPARE(s.binaryVersion,7);
        QCOMPARE(s.value(QStringLiteral("wan_proto")),QStringLiteral("4gdhcp"));
        QCOMPARE(s.recordCount,5);
    }

    void rejectsTruncatedFourFaithBinary(){
        QByteArray bytes("FOUR-FAITH:");
        bytes.append(char(7));
        bytes.append(char(9));
        bytes.append("wan_proto",9);
        bytes.append(char(10));bytes.append(char(0));
        bytes.append("4g",2);
        const NvramSnapshot s=NvramSnapshotParser::parse(bytes);
        QVERIFY(!s.valid);
        QVERIFY(!s.error.isEmpty());
    }

    void recognizesSensitiveKeys(){
        QVERIFY(NvramSnapshotParser::isSensitiveKey(QStringLiteral("http_passwd")));
        QVERIFY(NvramSnapshotParser::isSensitiveKey(QStringLiteral("easycwmp_acspassword")));
        QVERIFY(NvramSnapshotParser::isSensitiveKey(QStringLiteral("comm_iccid")));
        QVERIFY(!NvramSnapshotParser::isSensitiveKey(QStringLiteral("comm_rsrp")));
    }
};
QTEST_MAIN(TestNvramSnapshotParser)
#include "test_nvramsnapshotparser.moc"
