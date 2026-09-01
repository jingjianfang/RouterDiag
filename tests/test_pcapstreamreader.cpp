#include <QtTest>
#include <QSignalSpy>
#include "capture/PcapStreamReader.h"
static QByteArray le32(quint32 v){ QByteArray b; for(int i=0;i<4;i++) b.append(char((v>>(8*i))&0xff)); return b; }
static QByteArray le16(quint16 v){ QByteArray b; b.append(char(v&0xff)); b.append(char((v>>8)&0xff)); return b; }
static QByteArray sample(){ QByteArray b=QByteArray::fromHex("d4c3b2a1"); b+=le16(2)+le16(4)+le32(0)+le32(0)+le32(65535)+le32(1); b+=le32(1)+le32(2)+le32(4)+le32(4)+QByteArray::fromHex("01020304"); return b; }
class TestPcapStreamReader: public QObject {
    Q_OBJECT
private slots:
void fragmented(){ PcapStreamReader r; QSignalSpy h(&r,&PcapStreamReader::globalHeaderReady), p(&r,&PcapStreamReader::packetReady); auto s=sample(); r.appendData(s.left(7)); QCOMPARE(h.count(),0); r.appendData(s.mid(7,20)); QCOMPARE(h.count(),1); r.appendData(s.mid(27)); QCOMPARE(p.count(),1); auto rec=qvariant_cast<PcapRecord>(p.takeFirst().at(0)); QCOMPARE(rec.data,QByteArray::fromHex("01020304")); }
void invalidMagic(){ PcapStreamReader r; QSignalSpy e(&r,&PcapStreamReader::streamError); r.appendData(QByteArray(5000,'x')); QCOMPARE(e.count(),1); }
void finishDetectsTruncatedRecord(){ PcapStreamReader r; auto s=sample(); s.chop(2); r.appendData(s); QString e; QVERIFY(!r.finish(&e)); QVERIFY(!e.isEmpty()); }
void finishAcceptsCompleteStream(){ PcapStreamReader r; r.appendData(sample()); QString e; QVERIFY2(r.finish(&e),qPrintable(e)); }
};
QTEST_MAIN(TestPcapStreamReader)
#include "test_pcapstreamreader.moc"
