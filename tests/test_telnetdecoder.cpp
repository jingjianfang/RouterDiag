#include <QtTest>
#include "telnet/TelnetDecoder.h"
class TestTelnetDecoder : public QObject {
    Q_OBJECT
private slots:
void plain(){ TelnetDecoder d; QCOMPARE(d.feed("abc").payload, QByteArray("abc")); }
void escapedIac(){ TelnetDecoder d; QByteArray in; in.append(char(0xff)); in.append(char(0xff)); QCOMPARE(d.feed(in).payload, QByteArray(1,char(0xff))); }
void negotiation(){ TelnetDecoder d; auto r=d.feed(QByteArray::fromHex("fffb01")); QVERIFY(r.payload.isEmpty()); QCOMPARE(r.replyBytes, QByteArray::fromHex("fffe01")); }
void binaryNegotiation(){ TelnetDecoder d; QCOMPARE(d.feed(QByteArray::fromHex("fffb00")).replyBytes,QByteArray::fromHex("fffd00")); QCOMPARE(d.feed(QByteArray::fromHex("fffd00")).replyBytes,QByteArray::fromHex("fffb00")); }
void fragmented(){ TelnetDecoder d; QCOMPARE(d.feed(QByteArray::fromHex("41ff")).payload,QByteArray("A")); QCOMPARE(d.feed(QByteArray::fromHex("ff42")).payload,QByteArray::fromHex("ff42")); }
};
QTEST_MAIN(TestTelnetDecoder)
#include "test_telnetdecoder.moc"
