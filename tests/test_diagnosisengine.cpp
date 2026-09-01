#include <QtTest>
#include <QFile>
#include "diagnostic/LogAnalyzer.h"
#include "diagnostic/DiagnosisEngine.h"

class TestDiagnosisEngine: public QObject {
    Q_OBJECT
private slots:
    void cmeNotFatalWhenWanUp(){
        WanStatus s;
        s.moduleDetected=true;
        s.moduleAtResponsive=true;
        s.simStatus="READY";
        s.cgreg="0,1";
        s.cgatt=1;
        s.wanIp="10.0.0.2";
        s.cmeErrors.append({"AT+GMI",6003,"+CME ERROR: 6003"});
        QCOMPARE(DiagnosisEngine::diagnose(s).type,QString("WAN_NORMAL"));
    }

    void ipcpFailure(){
        WanStatus s;
        s.moduleDetected=true;
        s.moduleAtResponsive=true;
        s.simStatus="READY";
        s.pppConnected=true;
        s.cellularDialSeen=true;
        s.ipcpRequestCount=5;
        s.ipcpAckCount=0;
        s.wanNotUpCount=3;
        s.wanIp="0.0.0.0";
        QCOMPARE(DiagnosisEngine::diagnose(s).type,QString("CELLULAR_PPP_IPCP_FAILED"));
    }

    void atiOkCpinErrorIsSimNotModule(){
        WanStatus s;
        s.moduleAtResponsive=true;
        s.moduleName="N720";
        s.cpinErrorCount=3;
        s.simStatus="ERROR";
        s.wanIp="0.0.0.0";
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers.size(),4);
        QCOMPARE(layers[0].state, LayerState::Normal);
        QCOMPARE(layers[1].state, LayerState::Error);
        QVERIFY(layers[1].conclusion.contains("SIM"));
    }

    void readySimButRegistrationBad(){
        WanStatus s;
        s.moduleAtResponsive=true;
        s.simStatus="READY";
        s.cereg="0,8";
        s.cgreg="2,8";
        s.c5greg="2,4";
        s.wanIp="0.0.0.0";
        s.networkUnreachableCount=3;
        s.rsrp=-88;
        s.sinr=1;
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers[1].state, LayerState::Normal);
        QCOMPARE(layers[2].state, LayerState::Error);
        QVERIFY(layers[2].evidence.join(QStringLiteral("\n")).contains(QString::fromUtf8("SINR偏低")));
        QCOMPARE(layers[3].state, LayerState::NotTested);
        QVERIFY(layers[3].conclusion.contains(QString::fromUtf8("暂不具备有效测试条件")));
    }

    void validWanWinsOverAttachStatusNoise(){
        WanStatus s;
        s.moduleAtResponsive=true;
        s.simStatus="READY";
        s.cgatt=1;
        s.wanIp="10.4.106.210";
        QCOMPARE(DiagnosisEngine::diagnose(s).type, QString("WAN_NORMAL"));
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers[3].state,LayerState::Normal);
    }
    void extendedCeregUsesStatFieldNotAccessTechnology(){
        WanStatus s;s.moduleAtResponsive=true;s.simStatus="READY";s.cereg="2,1,\"1234\",\"56789ABC\",7";s.cgatt=1;s.wanIp="10.0.0.8";
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers.at(2).state,LayerState::Normal);
        QVERIFY(layers.at(2).evidence.join('\n').contains(QString::fromUtf8("LTE")));
    }

void limitedRegistrationIsNotReportedNormal(){
    WanStatus s;s.moduleAtResponsive=true;s.simStatus="READY";s.cereg="2,6,\"1234\",\"56789ABC\",7";
    const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
    QCOMPARE(layers.at(2).state,LayerState::Error);
    QVERIFY(layers.at(2).conclusion.contains(QString::fromUtf8("有限注册")));
}
    void zeroWanIpIsNotWanNormal(){
        WanStatus s;
        s.moduleAtResponsive=true;
        s.moduleDetected=true;
        s.simStatus="READY";
        s.cereg="2,1,\"1234\",\"56789ABC\",7";
        s.cgatt=1;
        s.wanIfname="ppp0";
        s.wanIp="0.0.0.0";
        const auto result=DiagnosisEngine::diagnose(s);
        QVERIFY(result.type!=QStringLiteral("WAN_NORMAL"));
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers.size(),4);
        QVERIFY(layers[2].state==LayerState::Normal);
        QVERIFY(layers[3].state!=LayerState::Normal);
        QVERIFY(layers[3].conclusion.contains(QStringLiteral("WAN IP")));
    }

    void invalidWanAddressesNeverMeanWanNormal(){
        for(const QString& ip:{QStringLiteral("0.0.0.0"),QStringLiteral("255.255.255.255"),QStringLiteral("::"),QStringLiteral("0:0:0:0:0:0:0:0")}){
            WanStatus s;s.moduleAtResponsive=true;s.simStatus="READY";s.cereg="2,1,\"1\",\"2\",7";s.cgatt=1;s.wanIp=ip;
            QVERIFY2(DiagnosisEngine::diagnose(s).type!=QStringLiteral("WAN_NORMAL"),qPrintable(ip));
        }
    }
    void registeredButZeroWanIpPointsToDataSessionNotRegistration(){
        WanStatus s;s.moduleAtResponsive=true;s.simStatus="READY";s.cereg="2,1,\"1\",\"2\",7";s.cgatt=1;s.wanIfname="ppp0";s.wanIp="0.0.0.0";
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers.at(2).state,LayerState::Normal);QCOMPARE(layers.at(3).state,LayerState::Warning);
        QVERIFY(layers.at(3).conclusion.contains(QString::fromUtf8("未获得有效 WAN IP")));
        QVERIFY(layers.at(3).suggestions.join('\n').contains(QStringLiteral("APN")));
    }
    void staleWanIpCannotOverrideCurrentInterfaceDown(){
        WanStatus s;s.wanIp="10.1.2.3";s.wanIfname="eth1";s.wanInterfaceStateKnown=true;s.wanInterfaceUp=false;
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);QCOMPARE(layers.at(3).state,LayerState::Error);
        QVERIFY(DiagnosisEngine::diagnose(s).type!=QStringLiteral("WAN_NORMAL"));
    }
    void validIpWithoutDefaultRouteIsOnlyWarning(){
        WanStatus s;s.wanIp="10.1.2.3";s.wanIfname="ppp0";s.wanInterfaceStateKnown=true;s.wanInterfaceUp=true;s.defaultRouteChecked=true;s.defaultRoutePresent=false;
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);QCOMPARE(layers.at(3).state,LayerState::Warning);
        QVERIFY(layers.at(3).conclusion.contains(QString::fromUtf8("默认路由")));
    }
    void moduleProbeNotAttemptedIsNotFailure(){
        WanStatus s;const auto layers=DiagnosisEngine::diagnoseWanLayers(s);QCOMPARE(layers.at(0).state,LayerState::NotTested);
        s.moduleProbeAttempted=true;s.moduleProbeCompleted=true;const auto completed=DiagnosisEngine::diagnoseWanLayers(s);QCOMPARE(completed.at(0).state,LayerState::Error);
    }

    void nvramSnapshotActiveIpIsHintNotWanNormal(){
        WanStatus s;
        s.nvramSnapshotPresent=true;s.wanIpFromNvramSnapshot=true;s.activeWanPath="primary";
        s.wanProto="4gdhcp";s.wanUp=1;s.wanIp="10.1.2.3";s.simStatus="READY";s.simStatusFromNvram=true;
        QCOMPARE(DiagnosisEngine::diagnose(s).type,QString("WAN_SNAPSHOT_ACTIVE_HINT"));
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers.at(3).state,LayerState::Warning);
        QCOMPARE(layers.at(3).confidence,Confidence::Medium);
        QVERIFY(layers.at(3).conclusion.contains(QString::fromUtf8("配置快照")));
    }

    void liveNvramStatusCanPopulateModuleSimAndRegistrationWithoutAt(){
        WanStatus s;
        s.moduleDetected=true;s.moduleName=QStringLiteral("NRLCM-M2");s.commModuleStatus=1;
        s.simStatus=QStringLiteral("READY");s.simStatusFromNvram=true;
        s.radioAccessMode=QStringLiteral("LTE");s.commDialStatus=1;
        s.wanIfname=QStringLiteral("eth1");s.wanIp=QStringLiteral("10.197.129.134");
        s.wanInterfaceStateKnown=true;s.wanInterfaceUp=true;
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QCOMPARE(layers.at(0).state,LayerState::Normal);
        QCOMPARE(layers.at(1).state,LayerState::Normal);
        QCOMPARE(layers.at(2).state,LayerState::Normal);
        QCOMPARE(layers.at(2).confidence,Confidence::Medium);
        QVERIFY(layers.at(2).conclusion.contains(QStringLiteral("NVRAM")));
    }

    void nvramRatHintDoesNotFabricateRegistration(){
        WanStatus s;s.nvramSnapshotPresent=true;s.moduleDetected=true;s.moduleName="L716-CN";
        s.simStatus="READY";s.simStatusFromNvram=true;s.radioAccessMode="FDD LTE";
        const auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QVERIFY(layers.at(2).state!=LayerState::Normal);
        QVERIFY(layers.at(2).conclusion.contains(QStringLiteral("CEREG")));
    }

    void snapshotAdviceRespectsThreeWanTopologies(){
        WanStatus s;s.nvramSnapshotPresent=true;s.wanIpFromNvramSnapshot=true;s.wanIp="10.1.2.3";s.activeWanPath="primary";
        s.wanTopology="primary-only";s.primaryWanPresent=true;
        auto layers=DiagnosisEngine::diagnoseWanLayers(s);
        QVERIFY(layers.at(3).conclusion.contains(QString::fromUtf8("仅主链路")));
        QVERIFY(!layers.at(3).suggestions.join('\n').contains(QString::fromUtf8("切换/优先级")));

        s.activeWanPath="backup";s.wanTopology="backup-only";s.primaryWanPresent=false;s.backupWanPresent=true;
        layers=DiagnosisEngine::diagnoseWanLayers(s);
        QVERIFY(layers.at(3).conclusion.contains(QString::fromUtf8("仅备链路")));
        QVERIFY(layers.at(3).suggestions.join('\n').contains(QString::fromUtf8("不要因主WAN为空")));

        s.activeWanPath="primary";s.wanTopology="dual";s.primaryWanPresent=true;s.backupWanPresent=true;
        layers=DiagnosisEngine::diagnoseWanLayers(s);
        QVERIFY(layers.at(3).conclusion.contains(QString::fromUtf8("主备双链")));
        QVERIFY(layers.at(3).suggestions.join('\n').contains(QString::fromUtf8("切换/优先级")));
    }

};
QTEST_MAIN(TestDiagnosisEngine)
#include "test_diagnosisengine.moc"
