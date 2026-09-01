#include <QtTest>
#include "diagnostic/DeviceDiscoveryController.h"

class TestDeviceDiscovery : public QObject {
    Q_OBJECT
private slots:
    void parsesBusyBoxIfconfigAndUsesWanHint(){
        const QString ifconfig=QString::fromUtf8(
            "br0       Link encap:Ethernet  HWaddr 00:11:22:33:44:55\n"
            "          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n"
            "          UP BROADCAST RUNNING MULTICAST\n"
            "ppp0      Link encap:Point-to-Point Protocol\n"
            "          inet addr:90.4.159.75  P-t-P:90.4.159.75  Mask:255.255.255.255\n"
            "          UP POINTOPOINT RUNNING NOARP MULTICAST\n");
        const auto r=DeviceDiscoveryParser::buildResult("ppp0\n","90.4.159.75\n",QString(),ifconfig);
        QCOMPARE(r.wanIfname,QString("ppp0"));
        QCOMPARE(r.wanIp,QString("90.4.159.75"));
        QCOMPARE(r.interfaces.size(),2);
        QCOMPARE(r.interfaces.at(1).name,QString("ppp0"));
        QCOMPARE(r.interfaces.at(0).netmask,QString("255.255.255.0"));
        QCOMPARE(r.interfaces.at(1).ipv4,QString("90.4.159.75"));
        QCOMPARE(r.interfaces.at(1).netmask,QString("255.255.255.255"));
        QVERIFY(r.interfaces.at(1).up);
    }

    void fallsBackToCellularLookingInterface(){
        const QString output=QString::fromUtf8(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 192.168.1.1/24 brd 192.168.1.255 scope global br0\n"
            "3: usb0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 10.4.106.210/30 brd 10.4.106.211 scope global usb0\n");
        const auto r=DeviceDiscoveryParser::buildResult(QString(),QString(),QString(),output);
        QCOMPARE(r.wanIfname,QString("usb0"));
        QCOMPARE(r.wanIp,QString("10.4.106.210"));
        QCOMPARE(r.interfaces.at(1).netmask,QString("255.255.255.0"));
        QCOMPARE(r.interfaces.at(2).netmask,QString("255.255.255.252"));
    }
    void prefersLiveWanInterfaceThenPrimaryThenBackup(){
        const QString ifconfig=QString::fromUtf8(
            "usb0 Link encap:Ethernet\n"
            "     inet addr:10.9.8.7 Bcast:10.9.8.11 Mask:255.255.255.252\n"
            "     UP RUNNING\n");
        auto live=DeviceDiscoveryParser::buildResult(QStringLiteral("usb0\n"),QStringLiteral("10.1.1.1\n"),QStringLiteral("10.2.2.2\n"),ifconfig);
        QCOMPARE(live.wanIp,QStringLiteral("10.9.8.7"));
        QVERIFY(live.wanIpSource.contains(QStringLiteral("接口")));

        auto backup=DeviceDiscoveryParser::buildResult(QStringLiteral("usb0\n"),QStringLiteral("0.0.0.0\n"),QStringLiteral("10.2.2.2\n"),QString());
        QVERIFY(backup.wanIp.isEmpty());
        QCOMPARE(backup.backupWanIp,QStringLiteral("10.2.2.2"));
    }

    void rejectsBridgeWanHintAndUsesRealWanCandidate(){
        const QString ifconfig=QString::fromUtf8(
            "br0 Link encap:Ethernet\n"
            "    inet addr:192.168.1.1 Bcast:192.168.1.255 Mask:255.255.255.0\n"
            "    UP RUNNING\n"
            "ppp0 Link encap:Point-to-Point Protocol\n"
            "     inet addr:10.20.30.40 P-t-P:10.20.30.40 Mask:255.255.255.255\n"
            "     UP RUNNING\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("br0\n"),QStringLiteral("192.168.1.1\n"),QString(),ifconfig);
        QCOMPARE(r.wanIfname,QStringLiteral("ppp0"));
        QCOMPARE(r.wanIp,QStringLiteral("10.20.30.40"));
    }

    void leavesWanUndetectedWhenOnlyLanBridgeExists(){
        const QString ifconfig=QString::fromUtf8(
            "br0 Link encap:Ethernet\n"
            "    inet addr:192.168.1.1 Bcast:192.168.1.255 Mask:255.255.255.0\n"
            "    UP RUNNING\n");
        const QString route=QStringLiteral("__FF_ROUTE_CHECK__\ndefault via 192.168.1.254 dev br0\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("br0\n"),QStringLiteral("192.168.1.1\n"),QString(),ifconfig,route);
        QVERIFY(r.wanIfname.isEmpty());
        QVERIFY(r.wanIp.isEmpty());
        QVERIFY(r.defaultRoutePresent);
        QCOMPARE(r.defaultRouteInterface,QStringLiteral("br0"));
    }

    void nvramWanHintOutranksDefaultRouteWhenIfconfigConfirmsIt(){
        const QString ifconfig=QString::fromUtf8(
            "vlan2 Link encap:Ethernet\n"
            "      inet addr:10.1.1.9 Bcast:10.1.1.255 Mask:255.255.255.0\n"
            "      UP RUNNING\n"
            "usb0 Link encap:Ethernet\n"
            "     inet addr:10.9.8.7 Bcast:10.9.8.11 Mask:255.255.255.252\n"
            "     UP RUNNING\n");
        const QString route=QStringLiteral("__FF_ROUTE_CHECK__\ndefault via 10.9.8.6 dev usb0\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("vlan2\n"),QStringLiteral("10.1.1.9\n"),QString(),ifconfig,route);
        QCOMPARE(r.defaultRouteInterface,QStringLiteral("usb0"));
        QCOMPARE(r.wanIfname,QStringLiteral("vlan2"));
        QCOMPARE(r.wanIp,QStringLiteral("10.1.1.9"));
        QVERIFY(r.wanIpSource.contains(QStringLiteral("NVRAM接口")));
        QVERIFY(r.wanIpSource.contains(QStringLiteral("wan_ifname")));
    }

    void backupWanNvramNameSelectsLiveIfconfigAddress(){
        const QString ifconfig=QString::fromUtf8(
            "br0 Link encap:Ethernet\n"
            "    inet addr:192.168.1.1 Bcast:192.168.1.255 Mask:255.255.255.0\n"
            "    UP RUNNING\n"
            "eth1 Link encap:Ethernet\n"
            "     inet addr:10.161.129.103 Bcast:10.161.129.111 Mask:255.255.255.240\n"
            "     UP RUNNING\n"
            "vlan2 Link encap:Ethernet\n"
            "      UP RUNNING\n");
        const QString route=QStringLiteral("__FF_ROUTE_CHECK__\ndefault via 10.161.129.97 dev vlan2\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QString(),QStringLiteral("0.0.0.0\n"),QStringLiteral("10.101.28.224\n"),ifconfig,route,
            QStringLiteral("eth1\n"),QStringLiteral("vlan2\n"),QStringLiteral("10.101.28.224\n"));
        QCOMPARE(r.wanIfname,QStringLiteral("eth1"));
        QCOMPARE(r.wanIp,QStringLiteral("10.161.129.103"));
        QCOMPARE(r.backupWanIp,QStringLiteral("10.101.28.224"));
        QCOMPARE(r.commWanIp,QStringLiteral("10.101.28.224"));
        QVERIFY(r.wanIpSource.contains(QStringLiteral("bkup_wan_ifname")));
    }


    void backupCardFlagPrioritizesBackupWanHint(){
        const QString ifconfig=QString::fromUtf8(
            "eth0 Link encap:Ethernet\n"
            "     inet addr:10.88.0.2 Bcast:10.88.0.3 Mask:255.255.255.252\n"
            "     UP RUNNING\n"
            "eth1 Link encap:Ethernet\n"
            "     inet addr:10.99.0.2 Bcast:10.99.0.3 Mask:255.255.255.252\n"
            "     UP RUNNING\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("eth1\n"),QStringLiteral("10.99.0.2\n"),QStringLiteral("10.88.0.2\n"),ifconfig,
            QString(),QStringLiteral("eth0\n"),QString(),QStringLiteral("10.88.0.2\n"),true);
        QCOMPARE(r.wanIfname,QStringLiteral("eth0"));
        QCOMPARE(r.wanIp,QStringLiteral("10.88.0.2"));
        QVERIFY(r.wanIpSource.contains(QStringLiteral("当前备卡")));
    }

    void interfaceInventoryKeepsVpnAndBridgeInterfaces(){
        const QString ifconfig=QString::fromUtf8(
            "br0 Link encap:Ethernet\n"
            "    inet addr:192.168.1.1 Bcast:192.168.1.255 Mask:255.255.255.0\n"
            "    UP RUNNING\n"
            "usb0 Link encap:Ethernet\n"
            "     inet addr:10.4.106.210 Bcast:10.4.106.211 Mask:255.255.255.252\n"
            "     UP RUNNING\n"
            "tun0 Link encap:UNSPEC\n"
            "     inet addr:172.20.0.2 P-t-P:172.20.0.1 Mask:255.255.255.255\n"
            "     UP POINTOPOINT RUNNING\n");
        const auto interfaces=DeviceDiscoveryParser::parseInterfaces(ifconfig);
        QStringList names;for(const auto& info:interfaces)names<<info.name;
        QVERIFY(names.contains(QStringLiteral("br0")));
        QVERIFY(names.contains(QStringLiteral("usb0")));
        QVERIFY(names.contains(QStringLiteral("tun0")));
    }

    void ignoresIfconfigStatisticLinesThatLookLikeNames(){
        const QString ifconfig=QString::fromUtf8(
            "br0       Link encap:Ethernet  HWaddr 54:D0:B4:73:A3:A4\n"
            "          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
            "          collisions:0 txqueuelen:0\n"
            "          Interrupt:3\n"
            "vlan2     Link encap:Ethernet  HWaddr 54:D0:B4:73:A3:A4\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n");
        const auto interfaces=DeviceDiscoveryParser::parseInterfaces(ifconfig);
        QStringList names;for(const auto& info:interfaces)names<<info.name;
        QCOMPARE(names,QStringList({QStringLiteral("br0"),QStringLiteral("vlan2")}));
        QVERIFY(!names.contains(QStringLiteral("collisions")));
        QVERIFY(!names.contains(QStringLiteral("Interrupt")));
    }

    void parsesModuleDeviceCandidatesAndAtResponses(){
        const QString devices=QString::fromUtf8(
            "CONTROL DEVICES /dev/ttyUSB2\n"
            "/dev/ttyUSB0\n/dev/ttyUSB2\n/dev/ttyACM0\n/dev/not-a-modem\n");
        const QStringList parsed=DeviceDiscoveryParser::parseModuleDevices(devices);
        QCOMPARE(parsed.size(),3);
        QCOMPARE(parsed.at(0),QString("/dev/ttyUSB2"));
        QCOMPARE(parsed.at(1),QString("/dev/ttyUSB0"));
        QCOMPARE(parsed.at(2),QString("/dev/ttyACM0"));

        QVERIFY(DeviceDiscoveryParser::atResponseOk("ATI\r\nQuectel\r\nEC200U-CN\r\nOK\r\n"));
        QCOMPARE(DeviceDiscoveryParser::parseAtValue("AT+CGMI\r\n+CGMI: Quectel\r\nOK\r\n",QStringLiteral("AT+CGMI")),QString("Quectel"));
        QCOMPARE(DeviceDiscoveryParser::parseAtValue("AT+CGMM\r\nEC200U-CN\r\nOK\r\n",QStringLiteral("AT+CGMM")),QString("EC200U-CN"));
        QCOMPARE(DeviceDiscoveryParser::parseAtValue("AT+CGMR\r\n+CGMR: EC200UCNAAR03A03M08\r\nOK\r\n",QStringLiteral("AT+CGMR")),QString("EC200UCNAAR03A03M08"));
        QCOMPARE(DeviceDiscoveryParser::parseAtiModel("ATI\r\nManufacturer: Quectel\r\nModel: RM500Q-GL\r\nRevision: R01\r\nOK\r\n"),QString("RM500Q-GL"));
    }


    void ignoresAtTestDecorationsAndParsesNeowayN511Ati(){
        const QString ati=QString::fromUtf8(
            "--> at\r\n"
            "--> ati\r\n"
            "<-- ati\r\n"
            "<--\r\n"
            "NEOWAY\r\n"
            "N511\r\n"
            "V006\r\n"
            " \r\n"
            "OK \r\n");
        QVERIFY(DeviceDiscoveryParser::atResponseOk(ati));
        QCOMPARE(DeviceDiscoveryParser::parseAtiManufacturer(ati),QStringLiteral("NEOWAY"));
        QCOMPARE(DeviceDiscoveryParser::parseAtiModel(ati),QStringLiteral("N511"));
        QCOMPARE(DeviceDiscoveryParser::parseAtiFirmware(ati),QStringLiteral("V006"));
    }

    void downConfiguredWanIsNotReportedAsActive(){
        const QString ifconfig=QString::fromUtf8(
            "vlan2 Link encap:Ethernet\n"
            "      BROADCAST MULTICAST  MTU:1500  Metric:1\n"
            "eth1 Link encap:Ethernet\n"
            "     inet addr:10.101.28.224 Bcast:10.101.28.255 Mask:255.255.255.0\n"
            "     UP BROADCAST RUNNING MULTICAST\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("vlan2\n"),QStringLiteral("10.10.10.10\n"),QStringLiteral("10.101.28.224\n"),ifconfig,
            QString(),QStringLiteral("eth1\n"),QString(),QStringLiteral("10.101.28.224\n"));
        QCOMPARE(r.wanIfname,QStringLiteral("eth1"));
        QCOMPARE(r.wanIp,QStringLiteral("10.101.28.224"));
        QVERIFY(r.wanInterfaceUp);
    }

    void downOnlyConfiguredWanDoesNotUseNvramIpAsLiveWan(){
        const QString ifconfig=QString::fromUtf8(
            "vlan2 Link encap:Ethernet\n"
            "      BROADCAST MULTICAST  MTU:1500  Metric:1\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("vlan2\n"),QStringLiteral("10.10.10.10\n"),QString(),ifconfig);
        QVERIFY(r.wanIfname.isEmpty());
        QVERIFY(r.wanIp.isEmpty());
    }

    void ignoresWanCommandEchoAndParsesActiveAtStatus(){
        const QString ifconfig=QString::fromUtf8(
            "eth1      Link encap:Ethernet\n"
            "          inet addr:10.189.141.87  Bcast:10.189.141.255  Mask:255.255.255.0\n"
            "          UP RUNNING\n");
        const auto r=DeviceDiscoveryParser::buildResult(
            QStringLiteral("nvram get wan_ifname\r\n#\r\n"),QString(),QString(),ifconfig);
        QVERIFY(r.wanIfname.isEmpty());
        QVERIFY(r.wanIp.isEmpty());
        QCOMPARE(DeviceDiscoveryParser::parseAtTaggedValue(
            QStringLiteral("AT+CPIN?\r\n+CPIN: READY\r\nOK\r\n"),QStringLiteral("+CPIN")),QStringLiteral("READY"));
        QCOMPARE(DeviceDiscoveryParser::parseAtTaggedValue(
            QStringLiteral("AT+CEREG?\r\n+CEREG: 2,5\r\nOK\r\n"),QStringLiteral("+CEREG")),QStringLiteral("2,5"));
    }

};

QTEST_MAIN(TestDeviceDiscovery)
#include "test_devicediscovery.moc"
