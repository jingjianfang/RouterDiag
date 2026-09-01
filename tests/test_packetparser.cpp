#include <QtTest>
#include "capture/PacketParser.h"
class TestPacketParser: public QObject {
    Q_OBJECT
private slots:
void ethernetTcp(){
    QByteArray f=QByteArray::fromHex("00112233445566778899aabb08004500002800000000400600000a0000010a00000204d2096400000001000000025012000000000000");
    PcapRecord r; r.data=f; r.includedLength=f.size();
    auto p=PacketParser::parse(r,PcapLinkType::Ethernet);
    QVERIFY(p.valid);
    QCOMPARE(p.protocol,QString("TCP"));
    QCOMPARE(p.sourceIp,QString("10.0.0.1"));
    QCOMPARE(p.destinationPort,quint16(2404));
    QVERIFY(p.tcpFlags & 0x02);
}
void tcpPayloadIsTransportPayloadOnly(){
    QByteArray f=QByteArray::fromHex(
        "00112233445566778899aabb0800"
        "4500002e00000000400600000a0000010a000002"
        "04d2096400000001000000025018000000000000"
        "680407000000");
    PcapRecord r; r.data=f; r.includedLength=f.size();
    auto p=PacketParser::parse(r,PcapLinkType::Ethernet);
    QVERIFY(p.valid);
    QCOMPARE(p.ipTotalLength,quint16(46));
    QCOMPARE(p.tcpHeaderLength,quint8(20));
    QCOMPARE(p.tcpPayloadLength,quint32(6));
    QCOMPARE(p.payload.toHex(),QByteArray("680407000000"));
    QCOMPARE(p.summary,QString("1234 → 2404 PSH-ACK"));
}
void snaplenTruncationBoundsPayload(){
    QByteArray f=QByteArray::fromHex(
        "00112233445566778899aabb0800"
        "4500003200000000400600000a0000010a000002"
        "04d2096400000001000000025018000000000000"
        "68040700");
    PcapRecord r; r.data=f; r.includedLength=f.size(); r.originalLength=14+50;
    auto p=PacketParser::parse(r,PcapLinkType::Ethernet);
    QVERIFY(p.valid);
    QCOMPARE(p.ipTotalLength,quint16(50));
    QCOMPARE(p.tcpPayloadLength,quint32(4));
    QCOMPARE(p.payload.toHex(),QByteArray("68040700"));
}

void qinqEthernetTcp(){
    QByteArray f=QByteArray::fromHex("00112233445566778899aabb88a800018100000208004500002800000000400600000a0000010a00000204d2096400000001000000025012000000000000");
    PcapRecord r;r.data=f;r.includedLength=f.size();const auto p=PacketParser::parse(r,PcapLinkType::Ethernet);QVERIFY(p.valid);QCOMPARE(p.destinationPort,quint16(2404));
}
void linuxSll2Tcp(){
    QByteArray f=QByteArray::fromHex("08000000000000010001000600112233445500004500002800000000400600000a0000010a00000204d2096400000001000000025012000000000000");
    PcapRecord r;r.data=f;r.includedLength=f.size();const auto p=PacketParser::parse(r,PcapLinkType::LinuxSll2);QVERIFY(p.valid);QCOMPARE(p.protocol,QString("TCP"));QCOMPARE(p.destinationPort,quint16(2404));
}
void truncated(){ PcapRecord r; r.data=QByteArray::fromHex("0011"); auto p=PacketParser::parse(r,PcapLinkType::Ethernet); QVERIFY(!p.valid); }
};
QTEST_MAIN(TestPacketParser)
#include "test_packetparser.moc"
