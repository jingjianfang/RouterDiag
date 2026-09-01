#include <QtTest>
#include <QSignalSpy>
#include "diagnostic/FieldWorkflowController.h"

class TestFieldWorkflowController : public QObject {
    Q_OBJECT
private slots:
    void ethernetWorkflowRunsAllNetworkStages(){
        FieldWorkflowController c;
        QSignalSpy actions(&c,&FieldWorkflowController::actionRequested);
        QSignalSpy finished(&c,&FieldWorkflowController::finished);
        FieldWorkflowConfig cfg;
        cfg.masterConfigured=true;
        cfg.terminalTransport=TerminalTransport::Ethernet;
        cfg.terminalConfigured=true;
        QString error;
        QVERIFY(c.start(cfg,&error));
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::DiscoverDevice));
        QCOMPARE(actions.count(),1);
        c.discoveryCompleted(true);
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::DiagnoseWan));
        c.wanDiagnosisCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::PingMaster));
        c.masterPingCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::CaptureMaster));
        c.masterCaptureCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::PingTerminal));
        c.terminalPingCompleted(true);
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::CaptureTerminal));
        c.terminalCaptureCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::Finished));
        QCOMPARE(finished.count(),1);
    }

    void unreachableEthernetTerminalStillCapturesTcpEvidence(){
        FieldWorkflowController c;
        FieldWorkflowConfig cfg;
        cfg.masterConfigured=true;
        cfg.terminalTransport=TerminalTransport::Ethernet;
        cfg.terminalConfigured=true;
        QVERIFY(c.start(cfg));
        c.discoveryCompleted(true);
        c.wanDiagnosisCompleted();
        c.masterPingCompleted();
        c.masterCaptureCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::PingTerminal));
        c.terminalPingCompleted(false);
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::CaptureTerminal));
        c.terminalCaptureCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::Finished));
    }

    void serialModeSkipsTerminalIpStages(){
        FieldWorkflowController c;
        FieldWorkflowConfig cfg;
        cfg.masterConfigured=true;
        cfg.terminalTransport=TerminalTransport::Serial;
        cfg.terminalConfigured=false;
        QVERIFY(c.start(cfg));
        c.discoveryCompleted(true);
        c.wanDiagnosisCompleted();
        c.masterPingCompleted();
        c.masterCaptureCompleted();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::Finished));
    }

    void rejectsMissingRequiredAddresses(){
        FieldWorkflowController c;
        FieldWorkflowConfig cfg;
        cfg.masterConfigured=false;
        cfg.terminalTransport=TerminalTransport::Ethernet;
        cfg.terminalConfigured=false;
        QString error;
        QVERIFY(!c.start(cfg,&error));
        QVERIFY(error.contains(QString::fromUtf8("主站")));
        QVERIFY(!c.isRunning());
    }

    void canCancelRunningWorkflow(){
        FieldWorkflowController c;
        FieldWorkflowConfig cfg;
        cfg.masterConfigured=true;
        cfg.terminalTransport=TerminalTransport::Serial;
        QVERIFY(c.start(cfg));
        c.cancel();
        QCOMPARE(int(c.step()),int(FieldWorkflowStep::Cancelled));
        QVERIFY(!c.isRunning());
    }
};

QTEST_MAIN(TestFieldWorkflowController)
#include "test_fieldworkflowcontroller.moc"
