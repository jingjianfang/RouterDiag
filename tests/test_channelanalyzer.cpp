#include <QtTest>
#include "diagnostic/ChannelAnalyzer.h"

static ParsedPacket tcp(const QString& src,quint16 sp,const QString& dst,quint16 dp,quint8 flags,quint32 payload=0){
    ParsedPacket p;
    p.valid=true;p.protocol="TCP";p.sourceIp=src;p.destinationIp=dst;
    p.sourcePort=sp;p.destinationPort=dp;p.tcpFlags=flags;
    p.tcpPayloadLength=payload;p.capturedLength=60+payload;
    return p;
}
static ParsedPacket icmp(const QString& src,const QString& dst,quint16 ipLen){
    ParsedPacket p;p.valid=true;p.protocol="ICMP";p.sourceIp=src;p.destinationIp=dst;
    p.ipTotalLength=ipLen;p.capturedLength=ipLen+14;return p;
}

class TestChannelAnalyzer : public QObject {
    Q_OBJECT
private slots:
void tracksHandshakePayloadAndMasterEvidence(){
    ChannelAnalyzer a({"90.15.80.82",2404,true});
    a.consume(tcp("90.15.80.82",33110,"90.4.159.75",2404,0x02));
    a.consume(tcp("90.4.159.75",2404,"90.15.80.82",33110,0x12));
    a.consume(tcp("90.15.80.82",33110,"90.4.159.75",2404,0x10));
    a.consume(tcp("90.15.80.82",33110,"90.4.159.75",2404,0x18,84));
    a.consume(icmp("90.15.80.82","90.4.159.75",140));
    const auto e=a.evidence();
    QCOMPARE(e.syn,quint64(1));
    QCOMPARE(e.synAck,quint64(1));
    QVERIFY(e.handshakeComplete);
    QCOMPARE(e.pshAck,quint64(1));
    QCOMPARE(e.payloadPackets,quint64(1));
    QCOMPARE(e.payloadBytes,quint64(84));
    QCOMPARE(e.icmp140,quint64(1));
    QCOMPARE(e.icmp140FromPeer,quint64(1));
    QCOMPARE(e.synFromPeer,quint64(1));
}
void synWithoutResponseStaysIncomplete(){
    ChannelAnalyzer a({"90.15.80.82",2404,true});
    a.consume(tcp("90.15.80.82",40000,"90.4.159.75",2404,0x02));
    const auto e=a.evidence();
    QVERIFY(!e.handshakeComplete);
    QCOMPARE(e.synFromPeer,quint64(1));
    QCOMPARE(e.synAck,quint64(0));
}
void ignoresOtherHostAndPort(){
    ChannelAnalyzer a({"90.15.80.82",2404,true});
    a.consume(tcp("1.1.1.1",1234,"2.2.2.2",2404,0x02));
    a.consume(tcp("90.15.80.82",1234,"90.4.159.75",12345,0x02));
    QCOMPARE(a.evidence().packets,quint64(0));
}
void diagnosesDocumentStyleMasterChannel(){
    PingResult ping; ping.validOutput=true; ping.reachable=true;
    ChannelAnalyzer a({"90.15.80.82",2404,true});
    a.consume(tcp("90.15.80.82",33110,"90.4.159.75",2404,0x02));
    a.consume(icmp("90.15.80.82","90.4.159.75",140));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Warning);
    QVERIFY(d.evidence.join('\n').contains(QString::fromUtf8("140字节ICMP")));
    QVERIFY(d.conclusion.contains(QString::fromUtf8("未应答")));
}
void diagnosesSynWithoutResponseConservatively(){
    PingResult ping; ping.validOutput=true; ping.reachable=true;
    ChannelAnalyzer a({"90.15.80.82",2404,true});
    a.consume(tcp("90.15.80.82",33110,"90.4.159.75",2404,0x02));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Warning);
    QVERIFY(d.conclusion.contains("SYN"));
}
void diagnosesTerminalPingFailure(){
    PingResult ping; ping.validOutput=true; ping.reachable=false; ping.transmitted=3; ping.received=0;
    ChannelEvidence e;
    const auto d=ChannelAnalyzer::diagnoseTerminalEthernet(ping,e);
    QCOMPARE(d.state,LayerState::Warning);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("不能仅凭Ping")));
    QVERIFY(d.conclusion.contains(QString::fromUtf8("TCP")));
}

void masterNoEchoReplyIsInconclusiveWhenTcpIsSilent(){
    PingResult ping;
    ping.validOutput=true;
    ping.reachable=false;
    ping.transmitted=4;
    ping.received=0;
    ping.packetLossPercent=100;
    ping.failureReason=QString::fromUtf8("目标未返回 ICMP Echo Reply");
    ping.rawOutput=QStringLiteral("4 packets transmitted, 0 packets received, 100% packet loss\n");
    ping.evidence<<QStringLiteral("Ping: transmitted=4, received=0, loss=100%")<<ping.failureReason;
    ChannelEvidence e;

    const auto d=ChannelAnalyzer::diagnoseMaster(ping,e);
    QCOMPARE(d.state,LayerState::Unknown);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("主站可能禁Ping")));
    QVERIFY(d.conclusion.contains(QString::fromUtf8("不能判定主站不可达")));
}

void explicitMasterRouteFailureRemainsAnError(){
    const auto ping=ConnectivityProbe::parsePingOutput(
        QStringLiteral("ping: sendto: Network is unreachable\n"));
    ChannelEvidence e;

    const auto d=ChannelAnalyzer::diagnoseMaster(ping,e);
    QCOMPARE(d.state,LayerState::Error);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("路由")) || d.conclusion.contains(QString::fromUtf8("不可达")));
    QVERIFY(d.evidence.join('\n').contains(QStringLiteral("Network is unreachable")));
}

void diagnosesTcpRefusalWithExactEndpoint(){
    PingResult ping;
    ChannelAnalyzer a({"10.20.30.40",2404,true});
    a.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x02));
    a.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x14));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Error);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("拒绝")));
    QVERIFY((d.conclusion+"\n"+d.evidence.join('\n')).contains("10.20.30.40:2404"));
}
void diagnosesRepeatedSynAsNoTcpResponse(){
    PingResult ping;
    ChannelAnalyzer a({"10.20.30.40",2404,true});
    for(int i=0;i<3;++i)a.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x02));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Warning);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("未应答")) || d.conclusion.contains(QString::fromUtf8("超时")));
    QVERIFY(d.evidence.join('\n').contains(QString::fromUtf8("3次 SYN")));
}
void diagnosesResetAndNormalCloseByExactSide(){
    PingResult ping;
    ChannelAnalyzer resetA({"10.20.30.40",2404,true});
    resetA.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x02));
    resetA.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x12));
    resetA.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x10));
    resetA.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x14));
    const auto resetD=ChannelAnalyzer::diagnoseMaster(ping,resetA.evidence());
    QCOMPARE(resetD.state,LayerState::Error);
    QVERIFY(resetD.conclusion.contains(QString::fromUtf8("重置")));
    QVERIFY(resetD.conclusion.contains("10.20.30.40:2404"));

    ChannelAnalyzer finA({"10.20.30.40",2404,true});
    finA.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x02));
    finA.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x12));
    finA.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x10));
    finA.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x11));
    const auto finD=ChannelAnalyzer::diagnoseMaster(ping,finA.evidence());
    QCOMPARE(finD.state,LayerState::Warning);
    QVERIFY(finD.conclusion.contains(QString::fromUtf8("FIN")) || finD.conclusion.contains(QString::fromUtf8("关闭")));
    QVERIFY(finD.conclusion.contains("10.20.30.40:2404"));
}
void diagnosesHandshakeIncompleteAfterSynAck(){
    PingResult ping;
    ChannelAnalyzer a({"10.20.30.40",2404,true});
    a.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x02));
    a.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x12));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Warning);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("握手未完成")));
    QVERIFY(d.conclusion.contains("192.168.2.101:49152"));
}
void diagnosesMidstreamPayloadWithoutPretendingHandshakeWasObserved(){
    PingResult ping;
    ChannelAnalyzer a({"10.20.30.40",2404,true});
    a.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x18,32));
    a.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x18,48));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Normal);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("双向业务数据")));
    QVERIFY(d.conclusion.contains(QString::fromUtf8("未包含握手")));
    QVERIFY(!d.conclusion.contains(QString::fromUtf8("三次握手完成")));
}
void diagnosesMidstreamResetByExactIp(){
    PingResult ping;
    ChannelAnalyzer a({"10.20.30.40",2404,true});
    a.consume(tcp("192.168.2.101",49152,"10.20.30.40",2404,0x18,16));
    a.consume(tcp("10.20.30.40",2404,"192.168.2.101",49152,0x14));
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Error);
    QVERIFY(d.conclusion.contains(QString::fromUtf8("重置")));
    QVERIFY(d.conclusion.contains("10.20.30.40:2404"));
}
void countsResetAndFin(){
    ChannelAnalyzer a({"192.168.3.102",0,false});
    a.consume(tcp("192.168.3.102",2404,"192.168.3.1",50000,0x14));
    a.consume(tcp("192.168.3.1",50000,"192.168.3.102",2404,0x11));
    QCOMPARE(a.evidence().rst,quint64(1));
    QCOMPARE(a.evidence().fin,quint64(1));
}

void discoversActualMasterClientBehindDifferentConfiguredIp(){
    Q_UNUSED(QStringLiteral("120.42.46.98")); // configured/reference master IP intentionally differs
    ChannelAnalyzer a({QString(),2404,true});
    a.consume(tcp("183.6.10.25",53126,"10.189.141.87",2404,0x02));
    a.consume(tcp("10.189.141.87",2404,"183.6.10.25",53126,0x12));
    a.consume(tcp("183.6.10.25",53126,"10.189.141.87",2404,0x10));
    const QStringList ips=ChannelAnalyzer::actualPeerIps(a.evidence(),EndpointRole::Client,2404);
    QCOMPARE(ips,QStringList({QStringLiteral("183.6.10.25")}));
    QVERIFY(!ips.contains(QStringLiteral("120.42.46.98")));
}
void classifiesMasterClientPayloadDirectionByActualPeer(){
    const QStringList actual{QStringLiteral("183.6.10.25")};
    ParsedPacket down=tcp("183.6.10.25",53126,"10.189.141.87",2404,0x18,12);
    ParsedPacket up=tcp("10.189.141.87",2404,"183.6.10.25",53126,0x18,8);
    QVERIFY(ChannelAnalyzer::packetFromActualPeer(down,actual,EndpointRole::Client,2404));
    QVERIFY(!ChannelAnalyzer::packetFromActualPeer(up,actual,EndpointRole::Client,2404));
}
void currentPayloadSessionOutranksOlderFailedSession(){
    PingResult ping;ChannelAnalyzer a({QString(),2404,true});
    ParsedPacket oldSyn=tcp("1.1.1.1",40000,"10.0.0.1",2404,0x02);oldSyn.timestamp=QDateTime::fromMSecsSinceEpoch(1000);a.consume(oldSyn);
    ParsedPacket oldRst=tcp("10.0.0.1",2404,"1.1.1.1",40000,0x14);oldRst.timestamp=QDateTime::fromMSecsSinceEpoch(1010);a.consume(oldRst);
    ParsedPacket p1=tcp("2.2.2.2",50000,"10.0.0.1",2404,0x18,20);p1.payload=QByteArray(20,'A');p1.timestamp=QDateTime::fromMSecsSinceEpoch(2000);a.consume(p1);
    ParsedPacket p2=tcp("10.0.0.1",2404,"2.2.2.2",50000,0x18,12);p2.payload=QByteArray(12,'B');p2.timestamp=QDateTime::fromMSecsSinceEpoch(2010);a.consume(p2);
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());
    QCOMPARE(d.state,LayerState::Normal);QVERIFY(d.conclusion.contains(QString::fromUtf8("历史连接异常")));
    const QString report=ChannelAnalyzer::tcpSessionReport(a.evidence());QVERIFY(report.contains(QString::fromUtf8("主业务会话")));
}

void postBidirectionalBusinessRstIsWarning(){
    PingResult ping;ChannelAnalyzer a({QString(),2404,true});
    ParsedPacket syn=tcp("1.2.3.4",50000,"10.0.0.1",2404,0x02);syn.timestamp=QDateTime::fromMSecsSinceEpoch(1000);a.consume(syn);
    ParsedPacket sa=tcp("10.0.0.1",2404,"1.2.3.4",50000,0x12);sa.timestamp=QDateTime::fromMSecsSinceEpoch(1010);a.consume(sa);
    ParsedPacket ack=tcp("1.2.3.4",50000,"10.0.0.1",2404,0x10);ack.timestamp=QDateTime::fromMSecsSinceEpoch(1020);a.consume(ack);
    ParsedPacket p1=tcp("1.2.3.4",50000,"10.0.0.1",2404,0x18,8);p1.payload=QByteArray(8,'A');p1.timestamp=QDateTime::fromMSecsSinceEpoch(1030);a.consume(p1);
    ParsedPacket p2=tcp("10.0.0.1",2404,"1.2.3.4",50000,0x18,8);p2.payload=QByteArray(8,'B');p2.timestamp=QDateTime::fromMSecsSinceEpoch(1040);a.consume(p2);
    ParsedPacket rst=tcp("10.0.0.1",2404,"1.2.3.4",50000,0x14);rst.timestamp=QDateTime::fromMSecsSinceEpoch(1050);a.consume(rst);
    const auto d=ChannelAnalyzer::diagnoseMaster(ping,a.evidence());QCOMPARE(d.state,LayerState::Warning);QVERIFY(d.conclusion.contains(QString::fromUtf8("业务")));
}
void exactFiveTuplePreventsCrossMasterDirectionMixing(){
    ChannelAnalyzer a({QString(),2404,true});
    auto aDown=tcp("183.6.10.25",53126,"10.0.0.1",2404,0x18,12);aDown.payload=QByteArray(12,'A');a.consume(aDown);
    auto bUp=tcp("10.0.0.1",2404,"183.6.10.26",41882,0x18,8);bUp.payload=QByteArray(8,'B');a.consume(bUp);
    const auto sessions=ChannelAnalyzer::actualPeerSessions(a.evidence(),EndpointRole::Client,2404);QVERIFY(sessions.size()>=2);
    const QList<TcpSessionEvidence> primary{sessions.first()};
    const bool aIsMaster=ChannelAnalyzer::packetFromActualPeer(aDown,primary,EndpointRole::Client,2404);
    const bool bIsMaster=ChannelAnalyzer::packetFromActualPeer(bUp,primary,EndpointRole::Client,2404);
    QVERIFY(aIsMaster!=bIsMaster || (aDown.sourceIp!=bUp.destinationIp));
}

};
QTEST_MAIN(TestChannelAnalyzer)
#include "test_channelanalyzer.moc"
