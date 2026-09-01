#include <QtTest>
#include <QSignalSpy>
#include <QTemporaryFile>
#include "capture/OfflinePcapController.h"

static QByteArray le32(quint32 v){ QByteArray b; for(int i=0;i<4;i++) b.append(char((v>>(8*i))&0xff)); return b; }
static QByteArray le16(quint16 v){ QByteArray b; b.append(char(v&0xff)); b.append(char((v>>8)&0xff)); return b; }

static QByteArray ethernetTcpFrame(quint32 seq, quint8 flags){
    QByteArray f=QByteArray::fromHex("00112233445566778899aabb08004500002800000000400600000a0000010a00000204d20964");
    f+=le32(seq);
    f+=QByteArray::fromHex("00000002");
    f.append(char(0x50));
    f.append(char(flags));
    f+=QByteArray::fromHex("000000000000");
    return f;
}

static QByteArray pcapWithTwoPackets(){
    QByteArray b=QByteArray::fromHex("d4c3b2a1");
    b+=le16(2)+le16(4)+le32(0)+le32(0)+le32(65535)+le32(1);
    const QByteArray a=ethernetTcpFrame(1,0x02);
    const QByteArray c=ethernetTcpFrame(2,0x10);
    b+=le32(100)+le32(0)+le32(a.size())+le32(a.size())+a;
    b+=le32(101)+le32(0)+le32(c.size())+le32(c.size())+c;
    return b;
}

static QByteArray pcapngWithOneEnhancedPacket(){
    const QByteArray frame=ethernetTcpFrame(7,0x18);
    const quint32 padded=(quint32(frame.size())+3u)&~3u;
    QByteArray b;
    // Section Header Block, little-endian, version 1.0, unknown section length.
    b+=QByteArray::fromHex("0a0d0d0a")+le32(28)+QByteArray::fromHex("4d3c2b1a")+le16(1)+le16(0)+QByteArray(8,char(0xff))+le32(28);
    // Interface Description Block: Ethernet, default timestamp resolution (microseconds).
    b+=le32(1)+le32(20)+le16(1)+le16(0)+le32(65535)+le32(20);
    // Enhanced Packet Block: interface 0, timestamp 1.5s, one Ethernet frame.
    const quint32 blockLen=32+padded;
    b+=le32(6)+le32(blockLen)+le32(0)+le32(0)+le32(1500000)+le32(frame.size())+le32(frame.size())+frame;
    b+=QByteArray(int(padded-frame.size()),char(0));
    b+=le32(blockLen);
    return b;
}

class TestOfflinePcapController: public QObject {
    Q_OBJECT
private slots:
    void loadAndAnalyzeAll(){
        OfflinePcapController c;
        QString error;
        QVERIFY2(c.loadData(pcapWithTwoPackets(),&error),qPrintable(error));
        QCOMPARE(c.packetCount(),2);
        QSignalSpy packetSpy(&c,&OfflinePcapController::packetReady);
        QSignalSpy statsSpy(&c,&OfflinePcapController::statsUpdated);
        c.analyzeAll();
        QCOMPARE(packetSpy.count(),2);
        QVERIFY(statsSpy.count()>=1);
        QCOMPARE(c.stats().totalPackets,quint64(2));
        QCOMPARE(c.stats().tcpPackets,quint64(2));
    }

    void loadsPcapngEnhancedPacket(){
        OfflinePcapController c;
        QString error;
        QVERIFY2(c.loadData(pcapngWithOneEnhancedPacket(),&error,QStringLiteral("sample.pcapng")),qPrintable(error));
        QCOMPARE(c.packetCount(),1);
        QCOMPARE(c.globalHeader().linkType,quint32(1));
        QSignalSpy packets(&c,&OfflinePcapController::packetReady);
        c.analyzeAll();
        QCOMPARE(packets.count(),1);
        QCOMPARE(c.stats().tcpPackets,quint64(1));
    }

    void loadFileDirectlyAnalyzesAndEmitsPackets(){
        QTemporaryFile file;
        QVERIFY(file.open());
        const QByteArray data=pcapWithTwoPackets();
        QCOMPARE(file.write(data),qint64(data.size()));
        file.flush();

        OfflinePcapController c;
        QSignalSpy packets(&c,&OfflinePcapController::packetReady);
        QSignalSpy progress(&c,&OfflinePcapController::loadProgress);
        QString error;
        QVERIFY2(c.loadFile(file.fileName(),&error),qPrintable(error));
        QCOMPARE(c.packetCount(),2);
        QCOMPARE(c.stats().totalPackets,quint64(2));
        QCOMPARE(packets.count(),2);
        QVERIFY(progress.count()>=1);
        QVERIFY(c.replayAvailable());
    }

    void rejectsTruncatedFile(){
        OfflinePcapController c;
        QByteArray data=pcapWithTwoPackets();
        data.chop(5);
        QString error;
        QVERIFY(!c.loadData(data,&error));
        QVERIFY(!error.isEmpty());
    }

    void fastestReplayFinishes(){
        OfflinePcapController c;
        QString error;
        QVERIFY(c.loadData(pcapWithTwoPackets(),&error));
        QSignalSpy finished(&c,&OfflinePcapController::replayFinished);
        QSignalSpy packets(&c,&OfflinePcapController::packetReady);
        c.startReplay(OfflinePcapController::ReplaySpeed::Fastest);
        QTRY_COMPARE(finished.count(),1);
        QCOMPARE(packets.count(),2);
    }
};
QTEST_MAIN(TestOfflinePcapController)
#include "test_offlinepcapcontroller.moc"
