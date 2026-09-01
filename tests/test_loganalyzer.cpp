#include <QtTest>
#include <QFile>
#include "diagnostic/LogAnalyzer.h"

class TestLogAnalyzer: public QObject {
    Q_OBJECT
private slots:
    void basic(){
        auto s=LogAnalyzer::analyze("FM650 detected\nMAIN LINK Q: AT+CPIN?\nMAIN LINK A:\n+CPIN: READY\n+CGREG: 2,1\n+CGATT: 1\n+CSQ: 20,99\n[data=wan_ipaddr  value=10.1.2.3]");
        QCOMPARE(s.simStatus,QString("READY"));
        QCOMPARE(s.cgreg,QString("2,1"));
        QCOMPARE(s.cgatt,1);
        QCOMPARE(s.wanIp,QString("10.1.2.3"));
    }

    void failureFixture(){
        QFile f(QFINDTESTDATA("fixtures/dial_failure.txt"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        auto s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
        QVERIFY(s.pppConnected);
        QVERIFY(s.ipcpRequestCount>0);
        QCOMPARE(s.ipcpAckCount,0);
        QVERIFY(s.wanNotUpCount>0);
    }

    void simErrorStillDetectsModule(){
        QFile f(QFINDTESTDATA("fixtures/sim_not_detected.txt"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        const WanStatus s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
        QVERIFY(s.moduleAtResponsive);
        QCOMPARE(s.moduleName, QString("N720"));
        QVERIFY(s.cpinErrorCount >= 2);
        QCOMPARE(s.simStatus, QString("ERROR"));
    }

    void registrationFixtureSeparatesSimAndRegistration(){
        QFile f(QFINDTESTDATA("fixtures/registration_failed.txt"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        const WanStatus s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
        QCOMPARE(s.simStatus, QString("READY"));
        QCOMPARE(s.cereg, QString("0,8"));
        QCOMPARE(s.cgreg, QString("2,8"));
        QCOMPARE(s.c5greg, QString("2,4"));
        QCOMPARE(s.wanIp, QString("0.0.0.0"));
        QVERIFY(s.networkUnreachableCount > 0);
    }

    void dtsTcpOverridesSerialConfigAsObservedTransport(){
        QFile f(QFINDTESTDATA("fixtures/normal_cellular_and_dts.txt"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        const WanStatus s=LogAnalyzer::analyze(QString::fromUtf8(f.readAll()));
        QCOMPARE(s.serialBaudrate, 115200);
        QCOMPARE(s.dcuIp, QString("192.168.2.101"));
        QCOMPARE(s.dcuPort, 2404);
        QVERIFY(s.southTcpConnected);
        QCOMPARE(s.observedTerminalTransport, QString("TCP"));
    }

    void attachStatusZeroDoesNotEraseValidWan(){
        const WanStatus s=LogAnalyzer::analyze(
            "4G_MAIN_Q: AT+CGATT?\n4G_MAIN_A:\n+CGATT: 1\nOK\n"
            "[data=wan_ipaddr  value=10.4.106.210]\n"
            "attach_check: status = 0, bret = 1, bOld = 1\n"
            "wanface=usb0\n");
        QCOMPARE(s.cgatt, 1);
        QCOMPARE(s.wanIp, QString("10.4.106.210"));
        QCOMPARE(s.wanIfname, QString("usb0"));
    }

    void parsesRsrpRsrqAndSinrVariants(){
        const WanStatus s=LogAnalyzer::analyze(
            "NR_RSRP: -96 dBm\n"
            "SS-RSRQ = -11 dB\n"
            "SINR: 18.7 dB\n");
        QCOMPARE(s.rsrp,-96);
        QCOMPARE(s.rsrq,-11);
        QCOMPARE(s.sinr,18);
    }

    void ttyUsbIsModuleControlEvidenceOnly(){
        const WanStatus s=LogAnalyzer::analyze(
            "CONTROL DEVICES /dev/ttyUSB2\n4G_MAIN_Q: ATI\n4G_MAIN_A:\nNEOWAY\nN720\nV009\nOK\n");
        QVERIFY(s.moduleAtResponsive);
        QCOMPARE(s.moduleControlDevice, QString("/dev/ttyUSB2"));
        QVERIFY(s.observedTerminalTransport != QString("SERIAL"));
    }
    void rejectsEchoedWanNvramCommandAsInterface(){
        const WanStatus s=LogAnalyzer::analyze(
            "$ nvram get wan_ifname\n"
            "nvram get wan_ifname\n"
            "#\n");
        QVERIFY(s.wanIfname.isEmpty());
    }

    void currentWanFailureClearsAfterRecoveryButHistoryRemains(){
        const WanStatus s=LogAnalyzer::analyze(
            "link down\nDHCP timeout\nwan network failed.\n"
            "link up\nDHCP bound 10.0.0.2\nwan is up\n");
        QVERIFY(!s.physicalLinkDown);QVERIFY(!s.dhcpFailure);QVERIFY(!s.wanNetworkFailed);
        QCOMPARE(s.physicalLinkDownCount,1);QCOMPARE(s.dhcpFailureCount,1);QCOMPARE(s.wanNetworkFailedCount,1);
    }
    void parsesOperatorSelection(){
        const WanStatus s=LogAnalyzer::analyze("+COPS: 0,0,\"China Mobile\",7\n");
        QCOMPARE(s.operatorName,QString("China Mobile"));QCOMPARE(s.operatorAccessTechnology,7);
    }

    void cmeSimNotInsertedGetsSpecificStatus(){
        const WanStatus s=LogAnalyzer::analyze("4G_MAIN_Q: AT+CPIN?\n4G_MAIN_A:\n+CME ERROR: 10\n");
        QCOMPARE(s.simStatus,QString::fromUtf8("SIM未插入"));QVERIFY(s.cpinErrorCount>0);
    }

    void nvramShowClassifiesBackupOnlyTopology(){
        const WanStatus s=LogAnalyzer::analyze(
            "wan_proto=disabled\nwanup=1\nwan_ipaddr=0.0.0.0\n"
            "bkup_wan_proto=4gdhcp1\nbkupwanup=1\nbkup_wan_ipaddr=10.20.30.40\n"
            "bkup_wan_ifname=eth1\ncomm_wan_ipaddr=10.20.30.40\n"
            "modulename=ME909\nsubmodulename=NRLCM-M2\ncomm_name=NRLCM-M2\n"
            "comm_module_status=1\ncomm_sim_card=1\ncomm_network=LTE\ncomm_rsrp=-98\n"
            "nvram_ver=3\n");
        QVERIFY(s.nvramSnapshotPresent);
        QCOMPARE(s.wanTopology,QString("backup-only"));
        QVERIFY(!s.primaryWanPresent);
        QVERIFY(s.backupWanPresent);
        QCOMPARE(s.activeWanPath,QString("backup"));
        QCOMPARE(s.wanIp,QString("10.20.30.40"));
        QCOMPARE(s.wanIfname,QString("eth1"));
        QCOMPARE(s.moduleName,QString("NRLCM-M2"));
        QVERIFY(s.moduleIdentityMismatch);
        QCOMPARE(s.rsrp,-98);
        QCOMPARE(s.simStatus,QString("READY"));
        QVERIFY(s.cereg.isEmpty()); // NVRAM RAT hints must not fabricate AT registration state.
    }

    void nvramShowSelectsSecondDtsProfileWhenItIsConnected(){
        const WanStatus s=LogAnalyzer::analyze(
            "wan_proto=disabled\nwan_ipaddr=0.0.0.0\nwanup=0\n"
            "dts_en=1\ndts_run=1\ndts_dcu_con_status=0\ndts_dcuip=192.168.50.11\ndts_dcuport=2404\n"
            "dts_dcu_con_status_2=1\ndts_dcuip_2=192.168.50.100\ndts_dcuport_2=2404\n"
            "dts_baudrate1=9600\ndts_baudrate2=115200\ndts_databit2=8\ndts_stopbit2=1\n"
            "nvram_ver=3\n");
        QCOMPARE(s.dtsActiveProfile,2);
        QCOMPARE(s.dtsDcuConStatus,0);
        QCOMPARE(s.dtsDcuConStatus2,1);
        QCOMPARE(s.dcuIp,QString("192.168.50.100"));
        QCOMPARE(s.dcuPort,2404);
        QCOMPARE(s.serialBaudrate,115200);
    }

    void nvramShowClassifiesPrimaryOnlyTopology(){
        const WanStatus s=LogAnalyzer::analyze(
            "wan_proto=4gdhcp\nwanup=1\nwan_ipaddr=10.30.40.50\nwan_ifname=eth0\n"
            "bkup_wan_proto=4gdhcp1\nbkupwanup=0\nbkup_wan_ipaddr=0.0.0.0\n"
            "comm_wan_ipaddr=10.30.40.50\nmodulename=FM650\ncurrent_module_real_name=L716-CN\ncomm_name=L716-CN\n"
            "comm_module_status=1\ncomm_dial_status=1\ncomm_sim_card=1\ncomm_network=FDD LTE\n"
            "comm_rsrp=-71\ncomm_rsrq=-7\ncomm_sinr=15\n"
            "dts_en=1\ndts_run=1\ndts_con_status=1\ndts_dcu_con_status=1\n"
            "dts_dcuip=192.168.60.15\ndts_dcuport=2404\ndts_baudrate1=115200\n"
            "nvram_ver=3\n");
        QCOMPARE(s.wanTopology,QString("primary-only"));
        QVERIFY(s.primaryWanPresent);
        QVERIFY(!s.backupWanPresent); // dormant/default bkup_* keys must not force dual topology.
        QCOMPARE(s.activeWanPath,QString("primary"));
        QCOMPARE(s.wanIp,QString("10.30.40.50"));
        QCOMPARE(s.moduleName,QString("L716-CN"));
        QCOMPARE(s.dtsConStatus,1);
        QCOMPARE(s.dtsDcuConStatus,1);
        QCOMPARE(s.dcuIp,QString("192.168.60.15"));
        QCOMPARE(s.dcuPort,2404);
        QCOMPARE(s.serialBaudrate,115200);
    }

    void nvramShowClassifiesDualTopology(){
        const WanStatus s=LogAnalyzer::analyze(
            "wan_proto=4gdhcp\nwanup=1\nwan_ipaddr=10.40.50.60\nwan_ifname=eth0\n"
            "bkup_wan_proto=4gdhcp1\nbkupwanup=1\nbkup_wan_ipaddr=10.40.60.70\nbkup_wan_ifname=eth1\n"
            "comm_wan_ipaddr=10.40.50.60\ncomm_dial_status=1\nnvram_ver=3\n");
        QCOMPARE(s.wanTopology,QString("dual"));
        QVERIFY(s.primaryWanPresent);
        QVERIFY(s.backupWanPresent);
        QCOMPARE(s.activeWanPath,QString("primary"));
        QCOMPARE(s.wanIp,QString("10.40.50.60"));
    }

};
QTEST_MAIN(TestLogAnalyzer)
#include "test_loganalyzer.moc"
