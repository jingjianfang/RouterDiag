#include <QtTest>
#include <QFile>
#include "diagnostic/DiagnosisEngine.h"
#include "protocol/ProtocolDiagnosis.h"
#include "report/ReportExporter.h"

class TestReportExporter : public QObject {
    Q_OBJECT
private slots:
    void fieldReportHasOrderedFourPresentationLayersAndNeutralUnknownState(){
        WanStatus wan;
        wan.moduleAtResponsive=true;
        wan.moduleName="N720";
        wan.simStatus="READY";
        wan.cereg="0,1";
        wan.wanIp="10.4.106.210";
        wan.wanIfname="usb0";

        FieldDiagnosisReport field;
        field.layers=DiagnosisEngine::diagnoseWanLayers(wan);
        LayerDiagnosis transport;
        transport.layer="TRANSPORT";
        transport.state=LayerState::NotTested;
        transport.confidence=Confidence::Low;
        transport.conclusion=QString::fromUtf8("主站与终端链路尚未测试");
        field.layers<<transport;
        field.overallConclusion=QString::fromUtf8("已完成WAN基础诊断，现场链路尚未测试");

        ProtocolEvidence protocol;
        protocol.layers=ProtocolDiagnosis::buildLayers(protocol);
        const QString report=ReportExporter::buildFieldReport(wan,field,protocol);

        const QStringList titles={
            QString::fromUtf8("[1] 模组 / SIM / 网络注册"),QString::fromUtf8("[2] WAN/IP"),
            QString::fromUtf8("[3] 主站与终端链路"),QString::fromUtf8("[4] 业务数据")
        };
        int previous=-1;
        for(const QString& title:titles){
            const int pos=report.indexOf(title);
            QVERIFY2(pos>previous,qPrintable(title));
            previous=pos;
        }
        QVERIFY(report.contains(QString::fromUtf8("四信路由器通信诊断工具")));
        QVERIFY(report.contains(QString::fromUtf8("状态: 未测试")));
        QVERIFY(!report.contains(QString::fromUtf8("状态: 异常\n结论: 主站与终端链路尚未测试")));
    }

    void repeated56WordingStaysConservative(){
        QFile f(QFINDTESTDATA("fixtures/grid_security_repeated_56.txt"));
        QVERIFY(f.open(QIODevice::ReadOnly));
        ProtocolEvidence protocol=ProtocolDiagnosis::analyzeLogText(QString::fromUtf8(f.readAll()));

        FieldDiagnosisReport field;
        for(const QString& name:{QString("CELLULAR_MODULE"),QString("SIM"),QString("REGISTRATION"),QString("WAN"),QString("TRANSPORT")}){
            LayerDiagnosis d;d.layer=name;d.state=LayerState::NotTested;d.conclusion=QString::fromUtf8("未测试");field.layers<<d;
        }
        const QString report=ReportExporter::buildFieldReport(WanStatus{},field,protocol);
        QVERIFY(report.contains(QString::fromUtf8("正常样本基线")));
        QVERIFY(report.contains(QString::fromUtf8("不一致")));
        QVERIFY(!report.contains(QString::fromUtf8("0x56 是非法命令")));
    }
};

QTEST_MAIN(TestReportExporter)
#include "test_reportexporter.moc"
