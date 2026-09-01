#include <QtTest>
#include "diagnostic/ConnectivityProbe.h"

class TestConnectivityProbe : public QObject {
    Q_OBJECT
private slots:
void validatesIpv4AndBuildsSafeCommand(){
    QVERIFY(ConnectivityProbe::isValidIpv4("192.168.3.102"));
    QVERIFY(!ConnectivityProbe::isValidIpv4("192.168.3.102;reboot"));
    QVERIFY(!ConnectivityProbe::isValidIpv4("2001:db8::1"));
    QVERIFY(ConnectivityProbe::isUsableWanIpv4("10.189.141.87"));
    QVERIFY(!ConnectivityProbe::isUsableWanIpv4("0.0.0.0"));
    QVERIFY(!ConnectivityProbe::isUsableWanIpv4("255.255.255.255"));
    QVERIFY(ConnectivityProbe::isUsableWanInterfaceName("ppp0"));
    QVERIFY(ConnectivityProbe::isUsableWanInterfaceName("usb0"));
    QVERIFY(ConnectivityProbe::isUsableWanInterfaceName("wwan0"));
    QVERIFY(!ConnectivityProbe::isUsableWanInterfaceName(" ppp0"));
    QVERIFY(!ConnectivityProbe::isUsableWanInterfaceName("br0"));
    QVERIFY(!ConnectivityProbe::isUsableWanInterfaceName("br-lan"));
    QVERIFY(!ConnectivityProbe::isUsableWanInterfaceName("lan0"));
    QVERIFY(!ConnectivityProbe::isUsableWanInterfaceName("lo"));
    QCOMPARE(ConnectivityProbe::buildPingCommand("192.168.3.102",3),QString("ping -c 3 192.168.3.102"));
    QCOMPARE(ConnectivityProbe::buildPingCommand("192.168.3.102;reboot",3),QString());
}
void comparesIpv4SubnetsUsingIfconfigNetmask(){
    QVERIFY(ConnectivityProbe::sameIpv4Subnet("192.168.1.100","192.168.1.1","255.255.255.0"));
    QVERIFY(!ConnectivityProbe::sameIpv4Subnet("192.168.4.100","192.168.1.1","255.255.255.0"));
    QVERIFY(ConnectivityProbe::sameIpv4Subnet("192.168.4.100","192.168.4.1","255.255.255.0"));
    QVERIFY(!ConnectivityProbe::sameIpv4Subnet("192.168.1.100","192.168.1.1","255.0.255.0"));
}
void parsesBusyBoxSuccess(){
    const auto r=ConnectivityProbe::parsePingOutput(
        "PING 192.168.3.102 (192.168.3.102): 56 data bytes\n"
        "64 bytes from 192.168.3.102: seq=0 ttl=64 time=0.5 ms\n"
        "--- 192.168.3.102 ping statistics ---\n"
        "3 packets transmitted, 3 packets received, 0% packet loss\n"
        "round-trip min/avg/max = 0.5/0.8/1.2 ms\n");
    QVERIFY(r.validOutput);
    QVERIFY(r.reachable);
    QCOMPARE(r.transmitted,3);
    QCOMPARE(r.received,3);
    QCOMPARE(r.packetLossPercent,0);
    QCOMPARE(r.avgRttMs,0.8);
    QVERIFY(r.rawOutput.contains(QStringLiteral("64 bytes from")));
}
void parsesLoss(){
    const auto r=ConnectivityProbe::parsePingOutput(
        "--- 192.168.3.102 ping statistics ---\n"
        "3 packets transmitted, 0 packets received, 100% packet loss\n");
    QVERIFY(r.validOutput);
    QVERIFY(!r.reachable);
    QCOMPARE(r.transmitted,3);
    QCOMPARE(r.received,0);
    QCOMPARE(r.packetLossPercent,100);
    QCOMPARE(r.failureKind,PingFailureKind::NoEchoReply);
    QVERIFY(!r.failureReason.isEmpty());
}
void parsesRouteFailureReason(){
    const auto r=ConnectivityProbe::parsePingOutput(QStringLiteral("ping: sendto: Network is unreachable\n"));
    QVERIFY(r.validOutput);
    QVERIFY(!r.reachable);
    QCOMPARE(r.failureKind,PingFailureKind::NetworkUnreachable);
    QVERIFY(r.failureReason.contains(QStringLiteral("Network is unreachable")));
}
void parsesDestinationHostUnreachableSeparatelyFromNoEcho(){
    const auto r=ConnectivityProbe::parsePingOutput(
        QStringLiteral("From 192.168.1.1 icmp_seq=1 Destination Host Unreachable\n"));
    QVERIFY(r.validOutput);
    QVERIFY(!r.reachable);
    QCOMPARE(r.failureKind,PingFailureKind::DestinationHostUnreachable);
    QVERIFY(r.failureReason.contains(QStringLiteral("Destination Host Unreachable")));
}

};
QTEST_MAIN(TestConnectivityProbe)
#include "test_connectivityprobe.moc"
