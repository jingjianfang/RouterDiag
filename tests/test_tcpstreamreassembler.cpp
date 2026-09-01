#include <QtTest>
#include "capture/TcpStreamReassembler.h"

static ParsedPacket tcpPayload(const QString& src,quint16 sp,const QString& dst,quint16 dp,quint32 seq,const QByteArray& payload)
{
    ParsedPacket p;
    p.valid=true;p.protocol=QStringLiteral("TCP");p.sourceIp=src;p.sourcePort=sp;p.destinationIp=dst;p.destinationPort=dp;
    p.sequence=seq;p.tcpPayloadLength=quint32(payload.size());p.payload=payload;
    return p;
}

class TestTcpStreamReassembler: public QObject {
    Q_OBJECT
private slots:
    void joinsSplitPayloadAndIgnoresRetransmission(){
        TcpStreamReassembler r;
        r.consume(tcpPayload("10.0.0.1",50000,"10.0.0.2",2404,100,QByteArray::fromHex("6804")));
        r.consume(tcpPayload("10.0.0.1",50000,"10.0.0.2",2404,102,QByteArray::fromHex("07000000")));
        r.consume(tcpPayload("10.0.0.1",50000,"10.0.0.2",2404,102,QByteArray::fromHex("07000000")));
        const auto dirs=r.directions();
        QCOMPARE(dirs.size(),1);
        QCOMPARE(dirs.first().bytes,QByteArray::fromHex("680407000000"));
    }
    void waitsForMissingOutOfOrderSegment(){
        TcpStreamReassembler r;
        r.consume(tcpPayload("10.0.0.1",50000,"10.0.0.2",2404,100,QByteArray("AB")));
        r.consume(tcpPayload("10.0.0.1",50000,"10.0.0.2",2404,104,QByteArray("EF")));
        QCOMPARE(r.directions().first().bytes,QByteArray("AB"));
        QVERIFY(r.directions().first().gapObserved);
        r.consume(tcpPayload("10.0.0.1",50000,"10.0.0.2",2404,102,QByteArray("CD")));
        QCOMPARE(r.directions().first().bytes,QByteArray("ABCDEF"));
    }
};

QTEST_MAIN(TestTcpStreamReassembler)
#include "test_tcpstreamreassembler.moc"
