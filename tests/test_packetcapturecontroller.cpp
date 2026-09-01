#include <QtTest>
#include "capture/PacketCaptureController.h"

class TestPacketCaptureController : public QObject {
    Q_OBJECT
private slots:
    void preflightUsesShellExitCodeInsteadOfEchoedMarkers(){
        const QString cmd=PacketCaptureController::buildPreflightCommand(
            QStringLiteral("br0"),QStringLiteral("host 192.168.1.111 and tcp port 2404"));
        QVERIFY(cmd.contains(QStringLiteral("command -v tcpdump")));
        QVERIFY(cmd.contains(QStringLiteral("ifconfig br0")));
        QVERIFY(cmd.contains(QStringLiteral("(exit 2)")));
        QVERIFY(!cmd.contains(QStringLiteral("__WANDIAG_NO_TCPDUMP__")));
        QVERIFY(!cmd.contains(QStringLiteral("__WANDIAG_NO_IFACE__")));
        QVERIFY(!cmd.contains(QStringLiteral("__WANDIAG_CAPTURE_OK__")));
        QVERIFY(!cmd.contains(QStringLiteral("tcpdump -i br0 -d")));
    }

    void binaryCommandKeepsStderrOutOfPcapStream(){
        const QString cmd=PacketCaptureController::buildTcpdumpCommand(
            QStringLiteral("br0"),QStringLiteral("host 192.168.1.111 and (icmp or tcp port 2404)"));
        QVERIFY(cmd.startsWith(QStringLiteral("exec tcpdump -i br0 -U -s 0 -w -")));
        QVERIFY(cmd.contains(QStringLiteral("'host 192.168.1.111 and (icmp or tcp port 2404)'")));
        QVERIFY(cmd.contains(QStringLiteral("2>/tmp/wandiag_tcpdump.err")));
        QVERIFY(!cmd.contains(QStringLiteral("stty raw -echo")));
    }

    void capturePtyIsPreparedBeforeBinaryCommand(){
        const QString cmd=PacketCaptureController::buildCapturePrepCommand();
        QVERIFY(cmd.contains(QStringLiteral("rm -f /tmp/wandiag_tcpdump.err")));
        QVERIFY(cmd.contains(QStringLiteral("stty raw -echo")));
        QCOMPARE(PacketCaptureController::buildErrorProbeCommand(),QStringLiteral("cat /tmp/wandiag_tcpdump.err 2>/dev/null"));
    }


    void serialTextCaptureRunsTcpdumpInBackgroundAndReturnsPid(){
        const QString cmd=PacketCaptureController::buildBackgroundTextTcpdumpCommand(
            QStringLiteral("eth1"),QStringLiteral("host 10.101.28.224"));
        QVERIFY(cmd.contains(QStringLiteral("tcpdump -i eth1 -n -l -s 0 -xx")));
        QVERIFY(cmd.contains(QStringLiteral("& pid=$!")));
        QVERIFY(cmd.contains(QStringLiteral("__WANDIAG_TCPDUMP_PID__=$pid")));
        QVERIFY(cmd.contains(QStringLiteral("'host 10.101.28.224'")));
    }

    void unsafeInterfaceCharactersAreRemoved(){
        const QString cmd=PacketCaptureController::buildPreflightCommand(
            QStringLiteral("br0;reboot"),QString());
        QVERIFY(!cmd.contains(QStringLiteral(";reboot")));
        QVERIFY(cmd.contains(QStringLiteral("br0reboot")));
    }
};
QTEST_MAIN(TestPacketCaptureController)
#include "test_packetcapturecontroller.moc"
