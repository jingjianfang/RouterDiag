#include <QtTest>
#include <QSignalSpy>
#include "capture/TcpdumpTextPcapConverter.h"
#include "capture/PcapStreamReader.h"

class TestTcpdumpTextPcapConverter : public QObject {
    Q_OBJECT
private slots:
    void convertsPuttyTcpdumpHexToClassicPcap(){
        const QByteArray text = R"LOG(=~=~=~=~=~=~=~= PuTTY log 2026.07.31 14:03:45 =~=~=~=~=~=~=~=
14:03:45.671698 IP (tos 0x0, ttl 64, id 42220, offset 0, flags [DF], proto TCP (6), length 40)
    172.18.12.62.9999 > 172.18.12.52.9999: Flags [.], length 0
        0x0000:  908f 2b50 3292 54d0 b476 b812 0800 4500
        0x0010:  0028 a4ec 4000 4006 254d ac12 0c3e ac12
        0x0020:  0c34 270f 270f cf28 0086 6112 319b 5010
        0x0030:  3908 70b1 0000
14:03:45.671879 IP (tos 0x0, ttl 128, id 1559, offset 0, flags [DF], proto TCP (6), length 40)
    172.18.12.52.9999 > 172.18.12.62.9999: Flags [.], length 0
        0x0000:  54d0 b476 b812 908f 2b50 3292 0800 4500
        0x0010:  0028 0617 4000 8006 8422 ac12 0c34 ac12
        0x0020:  0c3e 270f 270f 6112 319b cf28 0087 5010
        0x0030:  0800 86c2 0000 0000 0000 0000
)LOG";

        TcpdumpTextConversionResult result;
        QString error;
        QVERIFY2(TcpdumpTextPcapConverter::convert(text,&result,&error),qPrintable(error));
        QCOMPARE(result.packetCount,2);
        QCOMPARE(result.truncatedPacketCount,0);
        QCOMPARE(result.linkType,quint32(PcapLinkType::Ethernet));
        QVERIFY(result.pcapData.startsWith(QByteArray::fromHex("d4c3b2a1")));

        PcapStreamReader reader;
        QSignalSpy headers(&reader,&PcapStreamReader::globalHeaderReady);
        QSignalSpy packets(&reader,&PcapStreamReader::packetReady);
        reader.appendData(result.pcapData);
        QString finishError;
        QVERIFY2(reader.finish(&finishError),qPrintable(finishError));
        QCOMPARE(headers.count(),1);
        QCOMPARE(packets.count(),2);
        const auto first=qvariant_cast<PcapRecord>(packets.at(0).at(0));
        QCOMPARE(first.data.left(14),QByteArray::fromHex("908f2b50329254d0b476b8120800"));
    }

    void skipsTruncatedPacketInsteadOfInventingBytes(){
        const QByteArray text = R"LOG(PuTTY log 2026.07.31 14:03:45
14:03:45.671698 IP (tos 0x0, ttl 64, proto TCP (6), length 40)
        0x0000:  908f 2b50 3292 54d0 b476 b812 0800 4500
        0x0010:  0028 a4ec 4000 4006 254d ac12 0c3e ac12
14:03:46.000001 IP (tos 0x0, ttl 64, proto TCP (6), length 40)
        0x0000:  908f 2b50 3292 54d0 b476 b812 0800 4500
        0x0010:  0028 a4ec 4000 4006 254d ac12 0c3e ac12
        0x0020:  0c34 270f 270f cf28 0086 6112 319b 5010
        0x0030:  3908 70b1 0000
)LOG";
        TcpdumpTextConversionResult result;
        QString error;
        QVERIFY2(TcpdumpTextPcapConverter::convert(text,&result,&error),qPrintable(error));
        QCOMPARE(result.packetCount,1);
        QCOMPARE(result.truncatedPacketCount,1);
        QVERIFY(!result.warnings.isEmpty());
    }

    void failsWhenNoRecoverableHexFramesExist(){
        const QByteArray text = "PuTTY log 2026.07.31 14:03:45\n14:03:45.671698 IP length 40\n";
        TcpdumpTextConversionResult result;
        QString error;
        QVERIFY(!TcpdumpTextPcapConverter::convert(text,&result,&error));
        QVERIFY(error.contains(QString::fromUtf8("完整")) || error.contains(QString::fromUtf8("恢复")));
    }
    void convertsLinuxSll2AnyCapture(){
        const QByteArray text = R"LOG(PuTTY log 2026.08.30 00:01:00
00:01:00.000123 eth0 In IP 10.0.0.1.1234 > 10.0.0.2.2404: Flags [S], length 0
        0x0000:  0800 0000 0000 0001 0001 0006 0011 2233
        0x0010:  4455 0000 4500 0028 0000 0000 4006 0000
        0x0020:  0a00 0001 0a00 0002 04d2 0964 0000 0001
        0x0030:  0000 0002 5012 0000 0000 0000
)LOG";
        TcpdumpTextConversionResult result;QString error;
        QVERIFY2(TcpdumpTextPcapConverter::convert(text,&result,&error),qPrintable(error));
        QCOMPARE(result.packetCount,1);QCOMPARE(result.linkType,quint32(PcapLinkType::LinuxSll2));
    }

};

QTEST_MAIN(TestTcpdumpTextPcapConverter)
#include "test_tcpdumptextpcapconverter.moc"
