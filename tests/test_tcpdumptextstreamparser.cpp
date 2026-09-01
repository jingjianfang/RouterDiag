#include <QtTest>
#include <QSignalSpy>
#include "capture/TcpdumpTextStreamParser.h"
#include "capture/PcapStreamReader.h"
#include "capture/PacketParser.h"

class TestTcpdumpTextStreamParser: public QObject {
    Q_OBJECT
private slots:
void emitsCompletePacketBeforeStopForAnySll2(){
    TcpdumpTextStreamParser parser;
    parser.reset(QDate(2026,8,30));
    const QByteArray text=R"LOG(00:01:00.000123 eth0 In IP 10.0.0.1.1234 > 10.0.0.2.2404: Flags [S], length 0
        0x0000:  0800 0000 0000 0001 0001 0006 0011 2233
        0x0010:  4455 0000 4500 0028 0000 0000 4006 0000
        0x0020:  0a00 0001 0a00 0002 04d2 0964 0000 0001
        0x0030:  0000 0002 5012 0000 0000 0000
)LOG";
    const QByteArray pcap=parser.feed(text);
    QVERIFY(!pcap.isEmpty());
    QCOMPARE(parser.packetCount(),quint64(1));

    PcapStreamReader reader;QSignalSpy packets(&reader,&PcapStreamReader::packetReady);
    reader.appendData(pcap);QString error;QVERIFY2(reader.finish(&error),qPrintable(error));
    QCOMPARE(packets.count(),1);
    const PcapRecord record=qvariant_cast<PcapRecord>(packets.at(0).at(0));
    const ParsedPacket parsed=PacketParser::parse(record,PcapLinkType::LinuxSll2);
    QVERIFY(parsed.valid);QCOMPARE(parsed.destinationPort,quint16(2404));
}
};
QTEST_MAIN(TestTcpdumpTextStreamParser)
#include "test_tcpdumptextstreamparser.moc"
