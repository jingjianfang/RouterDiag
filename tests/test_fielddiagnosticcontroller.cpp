#include <QtTest>
#include "diagnostic/FieldDiagnosticController.h"
#include "diagnostic/DiagnosticController.h"
#include "capture/PacketCaptureController.h"
#include "telnet/TelnetClient.h"

class TestFieldDiagnosticController : public QObject {
    Q_OBJECT
private slots:
void buildsMasterDiscoveryAndTerminalFilters(){
    FieldDiagnosticConfig c;
    c.masterIp="90.15.80.82";c.masterPort=2404;
    c.terminalTransport=TerminalTransport::Ethernet;c.terminalIp="192.168.3.102";c.terminalPort=9999;
    QCOMPARE(FieldDiagnosticController::buildMasterFilter(c),QString("((host 90.15.80.82 and icmp) or tcp port 2404)"));
    QCOMPARE(FieldDiagnosticController::buildTerminalFilter(c),QString("host 192.168.3.102 and (icmp or tcp port 9999)"));
}
void serialModeHasNoTerminalNetworkProbe(){
    FieldDiagnosticConfig c;
    c.terminalTransport=TerminalTransport::Serial;c.terminalIp="192.168.3.102";
    QCOMPARE(FieldDiagnosticController::buildTerminalFilter(c),QString());
}
void rejectsUnsafeAddresses(){
    FieldDiagnosticConfig c;
    c.masterIp="90.15.80.82;reboot";c.masterPort=2404;
    c.terminalTransport=TerminalTransport::Ethernet;c.terminalIp="192.168.3.102 && reboot";
    QCOMPARE(FieldDiagnosticController::buildMasterFilter(c),QString());
    QCOMPARE(FieldDiagnosticController::buildTerminalFilter(c),QString());
}
void terminalCaptureCommandStreamsBr0ToStdout(){
    const QString cmd=PacketCaptureController::buildTcpdumpCommand("br0","host 192.168.3.102");
    QVERIFY(cmd.contains("tcpdump -i br0 -U -s 0 -w -"));
    QVERIFY(cmd.contains("host 192.168.3.102"));
    QVERIFY(!cmd.contains("-w /"));
    QVERIFY(!cmd.contains(".pcap"));
}
void idleDiagnosticControllerIgnoresUnrelatedCommands(){
    TelnetClient client;
    DiagnosticController controller(&client);
    QSignalSpy finished(&controller,&DiagnosticController::finished);
    client.commandFinished(QStringLiteral("ping -c 3 192.168.3.102"),
                           QStringLiteral("3 packets transmitted, 3 received"));
    QCOMPARE(finished.count(),0);
}
void automaticDiagnosisCommandsAreReadOnly(){
    const QString joined=DiagnosticController::automaticCommands().join("\n");
    QVERIFY(!joined.contains("nvram set",Qt::CaseInsensitive));
    QVERIFY(!joined.contains("nvram commit",Qt::CaseInsensitive));
    QVERIFY(joined.contains("nvram get debuglog_enable"));
    QVERIFY(joined.contains("nvram get syslogd_enable"));
}
};
QTEST_MAIN(TestFieldDiagnosticController)
#include "test_fielddiagnosticcontroller.moc"
