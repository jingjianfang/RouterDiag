#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "telnet/TelnetClient.h"
#include "diagnostic/DiagnosticController.h"
#include "diagnostic/LogAnalyzer.h"
#include "diagnostic/DiagnosisEngine.h"
#include "diagnostic/FieldDiagnosticController.h"
#include "diagnostic/DeviceDiscoveryController.h"
#include "diagnostic/ChannelAnalyzer.h"
#include "diagnostic/ConnectivityProbe.h"
#include "diagnostic/AtStatusParser.h"
#include "protocol/Iec104SessionAnalyzer.h"
#include "capture/PacketCaptureController.h"
#include "capture/OfflinePcapController.h"
#include "capture/TcpdumpTextPcapConverter.h"
#include "report/ReportExporter.h"
#include "ui/RemoteToolDialog.h"
#include "ui/DetachableTabWidget.h"
#include "ui/DetachablePanelManager.h"
#include "ui/CaptureSessionWidget.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QEventLoop>
#include <QPlainTextEdit>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QBoxLayout>
#include <QColor>
#include <QBrush>
#include <QFontDatabase>
#include <QCompleter>
#include <QAbstractItemView>
#include <QAbstractSpinBox>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QSaveFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QLabel>
#include <QRegularExpression>
#include <QPushButton>
#include <QResizeEvent>
#include <QGridLayout>
#include <QLayoutItem>
#include <QScrollArea>
#include <QStyle>
#include <QSpinBox>
#include <QSplitter>
#include <QSizePolicy>
#include <QLineEdit>
#include <QSettings>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QToolButton>
#include <QTime>
#include <QTextCursor>
#include <QScrollBar>
#include <QStatusBar>
#include <QSerialPortInfo>
#include <QTimer>
#include <QVariant>
#include <QEvent>

namespace {

bool plausibleModuleCardValue(const QString& value)
{
    const QString v=value.trimmed();
    if(v.isEmpty()||v.size()>80||v.contains(QLatin1Char(';'))||v.contains(QLatin1Char('$')))return false;
    const QString lower=v.toLower();
    const QStringList shellTokens={QStringLiteral("cat "),QStringLiteral("printf "),QStringLiteral("/tmp/"),QStringLiteral("/dev/"),
        QStringLiteral("sleep "),QStringLiteral("kill "),QStringLiteral("wait "),QStringLiteral("at_test"),QStringLiteral("__ff_at_")};
    for(const QString& token:shellTokens)if(lower.contains(token))return false;
    static const QRegularExpression valueRe(QStringLiteral(R"(^[A-Za-z0-9][A-Za-z0-9_.+ /()-]{0,79}$)"));
    return valueRe.match(v).hasMatch();
}

int layerRank(LayerState state)
{
    switch(state){
    case LayerState::Error:return 4;
    case LayerState::Warning:return 3;
    case LayerState::Normal:return 2;
    case LayerState::Unknown:return 1;
    case LayerState::NotTested:return 0;
    }
    return 0;
}

void appendUnique(QStringList& target,const QStringList& source)
{
    for(const QString& value:source)
        if(!value.isEmpty()&&!target.contains(value))target<<value;
}

QStringList tcpOutcomeSummaries(const LayerDiagnosis& transport)
{
    QStringList results;
    for(const QString& evidence:transport.evidence){
        const bool endpointLine=evidence.startsWith(QStringLiteral("主站链路：")) ||
                                evidence.startsWith(QStringLiteral("终端网口链路："));
        if(!endpointLine || !evidence.contains(QStringLiteral("TCP"),Qt::CaseInsensitive))continue;
        if(evidence.contains(QStringLiteral("尚未测试")) || evidence.contains(QStringLiteral("将分析")) ||
           evidence.contains(QStringLiteral("暂不做失败判定")))continue;
        if(!results.contains(evidence))results<<evidence;
    }
    return results;
}

QString layerStateText(LayerState state)
{
    switch(state){
    case LayerState::Normal:return QStringLiteral("正常");
    case LayerState::Warning:return QStringLiteral("关注");
    case LayerState::Error:return QStringLiteral("异常");
    case LayerState::NotTested:return QStringLiteral("未测试");
    default:return QStringLiteral("未知");
    }
}

QString cardStateText(LayerState state)
{
    switch(state){
    case LayerState::Normal:return QStringLiteral("正常");
    case LayerState::Warning:return QStringLiteral("关注");
    case LayerState::Error:return QStringLiteral("ERROR");
    case LayerState::NotTested:return QStringLiteral("未测试");
    case LayerState::Unknown:return QStringLiteral("未识别");
    }
    return QStringLiteral("未识别");
}

QString moduleCardText(const QString& model,LayerState fallbackState)
{
    const QString m=model.trimmed();
    if(plausibleModuleCardValue(m))return m;
    return cardStateText(fallbackState);
}





QString confidenceText(Confidence confidence)
{
    switch(confidence){
    case Confidence::High:return QStringLiteral("高");
    case Confidence::Medium:return QStringLiteral("中");
    default:return QStringLiteral("低");
    }
}

QString layerTitle(const QString& layer)
{
    if(layer==QStringLiteral("ACCESS"))return QStringLiteral("1 模组 / SIM / 网络注册");
    if(layer==QStringLiteral("CELLULAR_MODULE"))return QStringLiteral("模组/AT");
    if(layer==QStringLiteral("SIM"))return QStringLiteral("SIM卡");
    if(layer==QStringLiteral("REGISTRATION"))return QStringLiteral("网络注册");
    if(layer==QStringLiteral("WAN"))return QStringLiteral("2 WAN/IP");
    if(layer==QStringLiteral("TRANSPORT"))return QStringLiteral("3 主站与终端链路");
    if(layer==QStringLiteral("BUSINESS_DATA"))return QStringLiteral("4 业务数据");
    return layer;
}

void setStatusCard(QLabel* label,const QString& title,const QString& value,LayerState state)
{
    if(!label)return;
    QString stateName=QStringLiteral("unknown");
    switch(state){
    case LayerState::Normal:stateName=QStringLiteral("normal");break;
    case LayerState::Warning:stateName=QStringLiteral("warning");break;
    case LayerState::Error:stateName=QStringLiteral("error");break;
    case LayerState::NotTested:stateName=QStringLiteral("untested");break;
    case LayerState::Unknown:break;
    }
    label->setWordWrap(true);
    const QString cardValue=value.isEmpty()?QStringLiteral("--"):value;
    label->setText(QStringLiteral("%1\n%2").arg(title,cardValue));
    label->setMinimumHeight(cardValue.contains(QLatin1Char('\n'))?76:58);
    label->setProperty("state",stateName);
    label->style()->unpolish(label);
    label->style()->polish(label);
    label->update();
}

void clearLayoutItems(QLayout* layout)
{
    if(!layout)return;
    while(QLayoutItem* item=layout->takeAt(0)){
        // Nested layouts are themselves QLayoutItems. Keep them alive so responsive
        // reflow can safely add the same layout back at a new grid position.
        if(item->layout())continue;
        delete item;
    }
}
}


bool MainWindow::eventFilter(QObject* watched,QEvent* event)
{
    if(event && event->type()==QEvent::MouseButtonRelease){
        if(watched==ui->labelCardWan||watched==ui->labelCardModule||watched==ui->labelCardSim||
           watched==ui->labelCardRegistration||watched==ui->labelCardWanIp||watched==ui->labelCardSignal){
            openStatusCardDetail(watched);
            return true;
        }
    }
    return QMainWindow::eventFilter(watched,event);
}

MainWindow::MainWindow(QWidget* parent)
    :QMainWindow(parent),
      ui(new Ui::MainWindow),
      m_control(new TelnetClient(this)),
      m_capture(new TelnetClient(this)),
      m_moduleLog(new TelnetClient(this)),
      m_diag(nullptr),
      m_fieldDiag(nullptr),
      m_workflow(nullptr),
      m_discovery(nullptr),
      m_capCtrl(nullptr),
      m_offline(nullptr){
    ui->setupUi(this);
    setupCaptureInterfaceSelector();
    setupSerialCaptureWorkspace();
    setupDetachableTabs();
    setWindowTitle(QStringLiteral("四信路由器通信诊断工具"));
    m_diag=new DiagnosticController(m_control,this);
    m_fieldDiag=new FieldDiagnosticController(m_control,this);
    m_workflow=new FieldWorkflowController(this);
    m_discovery=new DeviceDiscoveryController(m_control,this);
    m_capCtrl=new PacketCaptureController(m_control,m_capture,this);
    m_offline=new OfflinePcapController(this);
    m_workflowCaptureTimer=new QTimer(this);
    m_workflowCaptureTimer->setSingleShot(true);
    m_captureNoTrafficTimer=new QTimer(this);
    m_captureNoTrafficTimer->setSingleShot(true);
    m_captureNoTrafficTimer->setInterval(7000);
    m_serialPortRefreshTimer=new QTimer(this);
    m_serialPortRefreshTimer->setInterval(2000);
    m_protocolRefreshTimer=new QTimer(this);
    m_protocolRefreshTimer->setSingleShot(true);
    m_protocolRefreshTimer->setInterval(200);
    connect(m_protocolRefreshTimer,&QTimer::timeout,this,[this]{rebuildProtocolEvidenceFromStreams();});
    connect(m_control,&TelnetClient::visibleTextReceived,this,[this](const QString& text){
        if(m_controlLoggedIn && routerSerialMode() && ui->comboTerminalTransport->currentIndex()!=0)appendSerialConsoleText(text);
    });

    ui->tablePackets->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tablePackets->horizontalHeader()->setStretchLastSection(true);
    ui->tablePackets->verticalHeader()->setVisible(false);
    ui->tablePackets->verticalHeader()->setDefaultSectionSize(28);
    ui->tableInterfaces->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableInterfaces->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableInterfaces->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableLayerStatus->horizontalHeader()->setSectionResizeMode(0,QHeaderView::ResizeToContents);
    ui->tableLayerStatus->horizontalHeader()->setSectionResizeMode(1,QHeaderView::ResizeToContents);
    ui->tableLayerStatus->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Stretch);
    ui->tableLayerStatus->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableLayerStatus->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableLayerStatus->verticalHeader()->setVisible(false);
    ui->tableLayerStatus->setAlternatingRowColors(true);
    ui->tableInterfaces->verticalHeader()->setVisible(false);
    ui->tableInterfaces->setAlternatingRowColors(true);
    ui->tablePackets->setAlternatingRowColors(true);
    ui->tableLayerStatus->verticalHeader()->setDefaultSectionSize(32);
    ui->comboReplaySpeed->setCurrentIndex(3);
    ui->diagnosisSplitter->setStretchFactor(0,2);
    ui->diagnosisSplitter->setStretchFactor(1,3);
    ui->packetVerticalSplitter->setStretchFactor(0,4);
    ui->packetVerticalSplitter->setStretchFactor(1,1);
    ui->mainVerticalSplitter->setStretchFactor(0,1);
    ui->mainVerticalSplitter->setStretchFactor(1,0);
    ui->deviceDetailsPanel->hide();
    // “网口详情”只展示普通 ifconfig 实际返回的接口/IP/UP 状态。
    // WAN/NVRAM/自动检测摘要已有独立状态卡片，不混入这个详情面板。
    ui->labelWanSummary->hide();
    ui->labelAutoDetectStatus->hide();
    ui->captureAdvancedPanel->show();
    ui->checkDirectSave->hide();
    ui->groupRuntimeLog->hide();
    setupResizableWorkspace();
    setupRc13Workspace();
    m_globalStopDiagnosisButton=new QPushButton(QStringLiteral("停止诊断"),statusBar());
    m_globalStopDiagnosisButton->setObjectName(QStringLiteral("btnGlobalStopDiagnosis"));
    m_globalStopDiagnosisButton->setProperty("role","danger");
    m_globalStopDiagnosisButton->setToolTip(QStringLiteral("无论当前在哪个功能页，都可以立即停止正在运行的一键现场诊断"));
    m_globalStopDiagnosisButton->hide();
    statusBar()->addPermanentWidget(m_globalStopDiagnosisButton);
    connect(m_globalStopDiagnosisButton,&QPushButton::clicked,this,&MainWindow::cancelOneClickDiagnosis);
    applyProfessionalStyle();
    ui->centralwidget->setProperty("responsiveLayoutMode",QString());
    reflowResponsiveLayout(width());

    connect(ui->btnConnect,&QPushButton::clicked,this,&MainWindow::connectRouter);
    connect(ui->btnDisconnect,&QPushButton::clicked,this,&MainWindow::disconnectRouter);
    connect(ui->comboRouterConnectionMode,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){updateRouterConnectionModeUi();});
    connect(ui->btnRefreshSerialPorts,&QPushButton::clicked,this,&MainWindow::refreshSerialPorts);
    connect(m_serialPortRefreshTimer,&QTimer::timeout,this,[this]{
        if(routerSerialMode() && !m_control->isConnected() && !ui->comboPcSerialPort->view()->isVisible())refreshSerialPorts();
    });
    m_serialPortRefreshTimer->start();
    connect(ui->btnModuleLog,&QPushButton::clicked,this,&MainWindow::showModuleLog);
    connect(ui->btnCommandWindow,&QPushButton::clicked,this,&MainWindow::showCommandWindow);
    connect(ui->btnNewPingWindow,&QPushButton::clicked,this,&MainWindow::showPingWindow);
    connect(ui->btnClearLog,&QPushButton::clicked,ui->txtDiagnosis,&QPlainTextEdit::clear);
    connect(ui->btnToggleDeviceDetails,&QPushButton::clicked,this,[this]{
        const bool show=m_deviceDetailsPanelManager?!m_deviceDetailsPanelManager->isPanelVisible():ui->deviceDetailsPanel->isHidden();
        if(m_deviceDetailsPanelManager)m_deviceDetailsPanelManager->setPanelVisible(show);
        else ui->deviceDetailsPanel->setVisible(show);
        ui->btnToggleDeviceDetails->setText(show?QStringLiteral("收起网口详情"):QStringLiteral("查看网口详情"));
    });
    connect(ui->btnToggleCaptureAdvanced,&QPushButton::clicked,this,[this]{
        const bool show=ui->checkDirectSave->isHidden();
        ui->checkDirectSave->setVisible(show);
        ui->btnToggleCaptureAdvanced->setText(show?QStringLiteral("高级参数 ▲"):QStringLiteral("高级参数 ▼"));
    });
    connect(ui->btnToggleRuntimeLog,&QPushButton::clicked,this,[this]{
        const bool show=m_runtimeLogPanelManager?!m_runtimeLogPanelManager->isPanelVisible():ui->groupRuntimeLog->isHidden();
        if(m_runtimeLogPanelManager)m_runtimeLogPanelManager->setPanelVisible(show);
        else ui->groupRuntimeLog->setVisible(show);
        ui->btnToggleRuntimeLog->setText(show?QStringLiteral("隐藏运行日志"):QStringLiteral("显示运行日志"));
        if(show && ui->mainVerticalSplitter->sizes().value(1)<80)ui->mainVerticalSplitter->setSizes({650,180});
    });
    connect(ui->btnHidePingResult,&QPushButton::clicked,this,[this]{
        if(m_pingPanelManager)m_pingPanelManager->setPanelVisible(false);
        else ui->groupPingResult->hide();
    });
    connect(m_captureNoTrafficTimer,&QTimer::timeout,this,[this]{
        if(m_capCtrl && m_capCtrl->isRunning() && m_lastCaptureStats.totalPackets==0){
            updateCaptureActivityState(QStringLiteral("当前暂无匹配流量"),LayerState::Normal);
            statusBar()->showMessage(QStringLiteral("抓包正常运行，但当前过滤器暂无匹配报文"),5000);
        }
    });
    connect(ui->comboConnectionHistory,&QComboBox::textActivated,this,[this](const QString& host){if(!host.trimmed().isEmpty())ui->editHost->setText(host.trimmed());});
    connect(ui->tableInterfaces,&QTableWidget::cellDoubleClicked,this,[this](int row,int){
        if(auto* item=ui->tableInterfaces->item(row,0)){
            const QString iface=item->text().trimmed();
            setCaptureInterfaceText(iface);
            ui->labelAutoDetectStatus->setText(QStringLiteral("抓包接口已选择：%1（手工抓包选择不会改变WAN诊断结果）").arg(iface));
            updateCaptureModeUi();
        }
    });
    connect(ui->tableLayerStatus,&QTableWidget::cellClicked,this,[this](int row,int){showLayerDetail(row);});
    connect(ui->tablePackets,&QTableWidget::cellClicked,this,[this](int row,int){ui->checkFollowLatestPacket->setChecked(false);showPacketDetail(row);});
    connect(ui->btnDiagnose,&QPushButton::clicked,this,&MainWindow::diagnose);
    connect(ui->btnOneClickDiagnosis,&QPushButton::clicked,this,&MainWindow::oneClickDiagnosis);
    connect(ui->btnCancelOneClick,&QPushButton::clicked,this,&MainWindow::cancelOneClickDiagnosis);
    connect(ui->btnStartCapture,&QPushButton::clicked,this,&MainWindow::startCapture);
    connect(ui->btnStopCapture,&QPushButton::clicked,this,&MainWindow::stopCapture);
    connect(ui->btnExportPcap,&QPushButton::clicked,this,&MainWindow::exportPcap);
    connect(ui->btnSaveReport,&QPushButton::clicked,this,&MainWindow::saveReport);
    connect(ui->btnImportLog,&QPushButton::clicked,this,&MainWindow::importSystemLog);
    connect(ui->btnImportPcap,&QPushButton::clicked,this,&MainWindow::importPcap);
    connect(ui->btnConvertTcpdumpText,&QPushButton::clicked,this,&MainWindow::convertTcpdumpTextToPcap);
    connect(ui->btnReplayPcap,&QPushButton::clicked,this,&MainWindow::replayPcap);
    connect(ui->btnStopReplay,&QPushButton::clicked,this,&MainWindow::stopReplay);
    connect(ui->btnPingMaster,&QPushButton::clicked,this,&MainWindow::pingMaster);
    connect(ui->btnPingTerminal,&QPushButton::clicked,this,&MainWindow::pingTerminal);
    connect(ui->comboTerminalTransport,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){updateTerminalTransportUi();});
    connect(ui->comboCaptureMode,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int index){
        if(index==0 || index==1){
            QString detectedWan=!m_discoveredWanIfname.isEmpty()?m_discoveredWanIfname:m_lastStatus.wanIfname;
            if(ConnectivityProbe::isUsableWanInterfaceName(detectedWan))setCaptureInterfaceText(detectedWan);
        }else if(index==2 && ui->comboTerminalTransport->currentIndex()==0){
            setCaptureInterfaceText(autoTerminalCaptureInterface());
        }
        updateCaptureModeUi();updateConnectionUi();
    });
    connect(ui->editCaptureTarget,&QLineEdit::textChanged,this,[this](const QString& value){
        const int mode=ui->comboCaptureMode->currentIndex();
        if(mode==1){
            FieldDiagnosticConfig cfg=currentFieldConfig();cfg.masterIp=value.trimmed();cfg.masterPort=quint16(ui->spinCapturePort->value());
            ui->editFilter->setText(FieldDiagnosticController::buildMasterFilter(cfg));
            ui->labelCapturePlan->setText(QStringLiteral("当前：%1 · %2").arg(captureInterfaceText().isEmpty()?QStringLiteral("未选择接口"):captureInterfaceText(),ui->editFilter->text().trimmed().isEmpty()?QStringLiteral("全部流量"):ui->editFilter->text().trimmed()));
        }else if(mode==2){
            FieldDiagnosticConfig cfg=currentFieldConfig();cfg.terminalTransport=TerminalTransport::Ethernet;cfg.terminalIp=value.trimmed();cfg.terminalPort=quint16(ui->spinCapturePort->value());
            ui->editFilter->setText(FieldDiagnosticController::buildTerminalFilter(cfg));
            ui->labelCapturePlan->setText(QStringLiteral("当前：%1 · %2").arg(captureInterfaceText().isEmpty()?QStringLiteral("未选择接口"):captureInterfaceText(),ui->editFilter->text().trimmed().isEmpty()?QStringLiteral("全部流量"):ui->editFilter->text().trimmed()));
        }
    });
    connect(ui->spinCapturePort,qOverload<int>(&QSpinBox::valueChanged),this,[this](int value){
        const int mode=ui->comboCaptureMode->currentIndex();
        if(mode==1){
            FieldDiagnosticConfig cfg=currentFieldConfig();cfg.masterIp=ui->editCaptureTarget->text().trimmed();cfg.masterPort=quint16(value);
            ui->editFilter->setText(FieldDiagnosticController::buildMasterFilter(cfg));
            ui->labelCapturePlan->setText(QStringLiteral("当前：%1 · %2").arg(captureInterfaceText().isEmpty()?QStringLiteral("未选择接口"):captureInterfaceText(),ui->editFilter->text().trimmed().isEmpty()?QStringLiteral("全部流量"):ui->editFilter->text().trimmed()));
        }else if(mode==2){
            FieldDiagnosticConfig cfg=currentFieldConfig();cfg.terminalTransport=TerminalTransport::Ethernet;cfg.terminalIp=ui->editCaptureTarget->text().trimmed();cfg.terminalPort=quint16(value);
            ui->editFilter->setText(FieldDiagnosticController::buildTerminalFilter(cfg));
            ui->labelCapturePlan->setText(QStringLiteral("当前：%1 · %2").arg(captureInterfaceText().isEmpty()?QStringLiteral("未选择接口"):captureInterfaceText(),ui->editFilter->text().trimmed().isEmpty()?QStringLiteral("全部流量"):ui->editFilter->text().trimmed()));
        }
    });
    connect(ui->editMasterIp,&QLineEdit::textChanged,this,[this](const QString&){
        if(m_capCtrl && m_capCtrl->isRunning() && m_fieldCaptureMode==FieldCaptureMode::Master)return;
        m_masterPingAttempted=false;m_masterPing=PingResult{};m_masterChannelEvidence=ChannelEvidence{};
        if(ui->comboCaptureMode->currentIndex()==1)updateCaptureModeUi();
        renderFieldDiagnosis();
    });
    connect(ui->spinMasterPort,qOverload<int>(&QSpinBox::valueChanged),this,[this](int){
        if(m_capCtrl && m_capCtrl->isRunning() && m_fieldCaptureMode==FieldCaptureMode::Master)return;
        m_masterChannelEvidence=ChannelEvidence{};
        if(ui->comboCaptureMode->currentIndex()==1)updateCaptureModeUi();
        renderFieldDiagnosis();
    });
    connect(ui->editTerminalIp,&QLineEdit::textChanged,this,[this](const QString&){
        if(m_capCtrl && m_capCtrl->isRunning() && m_fieldCaptureMode==FieldCaptureMode::TerminalEthernet)return;
        m_terminalPingAttempted=false;m_terminalPing=PingResult{};m_terminalChannelEvidence=ChannelEvidence{};
        if(ui->comboCaptureMode->currentIndex()==2)updateCaptureModeUi();
        renderFieldDiagnosis();
    });
    connect(ui->spinTerminalPort,qOverload<int>(&QSpinBox::valueChanged),this,[this](int){
        if(m_capCtrl && m_capCtrl->isRunning() && m_fieldCaptureMode==FieldCaptureMode::TerminalEthernet)return;
        m_terminalChannelEvidence=ChannelEvidence{};
        if(ui->comboCaptureMode->currentIndex()==2)updateCaptureModeUi();
        renderFieldDiagnosis();
    });
    connect(ui->comboMasterRole,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){
        m_masterChannelEvidence=ChannelEvidence{};m_actualMasterIps.clear();m_actualMasterSessions.clear();m_masterDownstreamPayloads.clear();m_masterUpstreamPayloadPackets=0;
        if(ui->comboCaptureMode->currentIndex()==1)updateCaptureModeUi();
        renderFieldDiagnosis();
    });
    connect(ui->comboTerminalRole,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){
        m_terminalChannelEvidence=ChannelEvidence{};renderFieldDiagnosis();
    });
    connect(ui->spinExpectedConnectionSeconds,qOverload<int>(&QSpinBox::valueChanged),this,[this](int){renderFieldDiagnosis();});
    connect(m_captureIfaceCombo,&QComboBox::editTextChanged,this,[this](const QString&){updateCaptureModeUi();});

    connect(m_workflowCaptureTimer,&QTimer::timeout,this,[this]{
        if(m_syncWorkflowCaptureActive){
            log(QStringLiteral("一键诊断：同步抓包时间到，正在同时停止终端侧和主站侧抓包"));
            stopSynchronizedWorkflowCapture();
            return;
        }
        if(m_capCtrl&&m_capCtrl->isRunning()){
            log(QStringLiteral("一键诊断：抓包时间到，正在停止当前抓包"));
            m_capCtrl->stop();
        }
    });

    connect(m_workflow,&FieldWorkflowController::stepChanged,this,[this](FieldWorkflowStep step){
        ui->labelWorkflowState->setText(QStringLiteral("一键诊断：%1").arg(FieldWorkflowController::stepText(step)));
        updateConnectionUi();
        renderFieldDiagnosis();
    });
    connect(m_workflow,&FieldWorkflowController::actionRequested,this,&MainWindow::handleWorkflowAction);
    connect(m_workflow,&FieldWorkflowController::failed,this,[this](const QString& reason){
        log(QStringLiteral("一键现场诊断失败：%1").arg(reason));
        statusBar()->showMessage(QStringLiteral("一键诊断失败：%1").arg(reason),8000);
        updateConnectionUi();renderFieldDiagnosis();
    });
    connect(m_workflow,&FieldWorkflowController::finished,this,[this]{
        saveFieldHistory();
        log(QStringLiteral("一键现场诊断完成：%1").arg(currentFieldReport().overallConclusion));
        statusBar()->showMessage(QStringLiteral("一键现场诊断完成"),8000);
        ui->mainTabs->setCurrentWidget(ui->tabFieldDiagnosis);
        updateConnectionUi();renderFieldDiagnosis();
        const QList<LayerDiagnosis> layers=currentPresentationLayers();
        int bestRow=layers.isEmpty()?-1:0,best=-1;
        for(int i=0;i<layers.size();++i){const int rank=layerRank(layers.at(i).state);if(rank>best){best=rank;bestRow=i;}}
        if(bestRow>=0){ui->tableLayerStatus->selectRow(bestRow);showLayerDetail(bestRow);}
    });

    connect(m_discovery,&DeviceDiscoveryController::progress,this,[this](const QString& message){
        ui->labelAutoDetectStatus->setText(message);
        setStatusCard(ui->labelCardWan,QStringLiteral("WAN"),QStringLiteral("检测中"),LayerState::Unknown);
        log(message);
    });
    connect(m_discovery,&DeviceDiscoveryController::failed,this,[this](const QString& reason){
        ui->labelAutoDetectStatus->setText(QStringLiteral("自动检测失败：")+reason);
        log(QStringLiteral("网口自动检测: ")+reason);
        if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::DiscoverDevice)
            m_workflow->discoveryCompleted(false);
    });
    connect(m_discovery,&DeviceDiscoveryController::finished,this,[this](const DeviceDiscoveryResult& result){
        displayDeviceDiscovery(result);
        if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::DiscoverDevice){
            const FieldDiagnosticConfig cfg=currentFieldConfig();
            if(cfg.terminalTransport==TerminalTransport::Ethernet){
                QString subnetError;
                if(!validateTerminalLanSubnet(cfg.terminalIp,&subnetError)){
                    log(QStringLiteral("一键诊断：%1").arg(subnetError));
                    statusBar()->showMessage(subnetError,10000);
                    m_workflow->operationFailed(subnetError);
                    return;
                }
            }
            m_workflow->discoveryCompleted(!result.wanIfname.isEmpty());
        }
    });

    connect(m_control,&TelnetClient::commandFinished,this,[this](const QString& command,const QString& output){
        if(command!=QStringLiteral("ifconfig 2>/dev/null"))return;
        const auto parsedInterfaces=DeviceDiscoveryParser::parseInterfaces(output);
        m_discoveredInterfaces.clear();
        for(const auto& info:parsedInterfaces){
            if(!info.up)continue;
            m_discoveredInterfaces.append(info);
        }
        ui->tableInterfaces->setRowCount(0);
        for(const auto& info:m_discoveredInterfaces){
            const int row=ui->tableInterfaces->rowCount();
            ui->tableInterfaces->insertRow(row);
            ui->tableInterfaces->setItem(row,0,new QTableWidgetItem(info.name));
            ui->tableInterfaces->setItem(row,1,new QTableWidgetItem(info.ipv4));
            ui->tableInterfaces->setItem(row,2,new QTableWidgetItem(QStringLiteral("UP")));
        }
        rebuildCaptureInterfaceChoices();
        ui->labelAutoDetectStatus->setText(m_discoveredInterfaces.isEmpty()?QStringLiteral("ifconfig 未返回 UP 接口；仍可手工输入抓包接口"):QStringLiteral("已读取 %1 个 ifconfig UP 接口").arg(m_discoveredInterfaces.size()));
    });

    connect(m_diag,&DiagnosticController::progress,this,[this](const QString& s){log(s);});
    connect(m_diag,&DiagnosticController::failed,this,[this](const QString& s){
        log("错误: "+s);
        if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::DiagnoseWan)m_workflow->operationFailed(s);
    });
    connect(m_diag,&DiagnosticController::finished,this,[this](const WanStatus& s,const DiagnosisResult&,const QString&){
        WanStatus merged=s;
        // Live device discovery is based on ifconfig + explicit WAN NVRAM hints and
        // therefore outranks route/log heuristics used by the later diagnostic pass.
        if(ConnectivityProbe::isUsableWanInterfaceName(m_discoveredWanIfname))merged.wanIfname=m_discoveredWanIfname;
        if(ConnectivityProbe::isUsableWanIpv4(m_discoveredWanIp)){
            merged.wanIp=m_discoveredWanIp;
            merged.wanIpSource=m_discoveredWanIpSource;
            merged.wanIpFromNvramSnapshot=false;
        }
        if(merged.moduleName.isEmpty())merged.moduleName=m_lastStatus.moduleName;
        if(merged.firmware.isEmpty())merged.firmware=m_lastStatus.firmware;
        if(merged.moduleControlDevice.isEmpty())merged.moduleControlDevice=m_lastStatus.moduleControlDevice;
        merged.moduleAtResponsive=merged.moduleAtResponsive||m_lastStatus.moduleAtResponsive;
        merged.moduleDetected=merged.moduleDetected||m_lastStatus.moduleDetected;
        const DiagnosisResult diagnosis=DiagnosisEngine::diagnose(merged);
        applyDiagnosis(merged,diagnosis,ReportExporter::buildTextReport(merged,diagnosis));
        if(captureInterfaceText().isEmpty()&&!merged.wanIfname.isEmpty())setCaptureInterfaceText(merged.wanIfname);
        renderFieldDiagnosis();
        if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::DiagnoseWan)m_workflow->wanDiagnosisCompleted();
    });

    connect(m_fieldDiag,&FieldDiagnosticController::failed,this,[this](const QString& reason){
        m_fieldPingMode=FieldPingMode::None;
        log(QStringLiteral("现场诊断: ")+reason);
        if(m_workflow&&m_workflow->isRunning())m_workflow->operationFailed(reason);
        renderFieldDiagnosis();
    });
    connect(m_fieldDiag,&FieldDiagnosticController::pingStarted,this,[this](const QString& target){
        beginPingDisplay(target);
    });
    connect(m_fieldDiag,&FieldDiagnosticController::pingOutputReceived,this,[this](const QString& target,const QString& chunk){
        Q_UNUSED(target);
        appendPingDisplay(chunk);
    });
    connect(m_fieldDiag,&FieldDiagnosticController::pingFinished,this,[this](const QString& target,const PingResult& result){
        const FieldDiagnosticConfig cfg=currentFieldConfig();
        const FieldPingMode completed=m_fieldPingMode;
        m_fieldPingMode=FieldPingMode::None;
        finishPingDisplay(target,result);
        if(completed==FieldPingMode::Master && target==cfg.masterIp){
            m_masterPing=result;m_masterPingAttempted=true;
            renderFieldDiagnosis();
            if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::PingMaster){m_workflow->masterPingCompleted();return;}
        }
        if(completed==FieldPingMode::TerminalEthernet && cfg.terminalTransport==TerminalTransport::Ethernet && target==cfg.terminalIp){
            m_terminalPing=result;m_terminalPingAttempted=true;
            renderFieldDiagnosis();
            if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::PingTerminal){
                m_workflow->terminalPingCompleted(result.validOutput&&result.reachable);return;
            }
            if(result.validOutput && result.reachable){
                log(QStringLiteral("终端Ping成功，自动启动 %1 终端 %2:%3 抓包")
                    .arg(autoTerminalCaptureInterface()).arg(cfg.terminalIp).arg(cfg.terminalPort));
                QTimer::singleShot(0,this,&MainWindow::captureTerminal);
                return;
            }
        }
        renderFieldDiagnosis();
    });

    connect(m_capCtrl,&PacketCaptureController::packetReady,this,&MainWindow::appendPacket);
    connect(m_capCtrl,&PacketCaptureController::statsUpdated,this,&MainWindow::updateStats);
    connect(m_capCtrl,&PacketCaptureController::captureStarting,this,[this](const QString& status){
        setCaptureState(status,LayerState::Warning);
        statusBar()->showMessage(status);
        updateConnectionUi();
    });
    connect(m_capCtrl,&PacketCaptureController::captureError,this,[this](const QString& e){
        if(m_captureNoTrafficTimer)m_captureNoTrafficTimer->stop();
        setCaptureState(QStringLiteral("启动失败：%1").arg(e),LayerState::Error);
        statusBar()->showMessage(QStringLiteral("抓包失败：%1").arg(e),7000);
        log("抓包错误: "+e);
        updateConnectionUi();
        if(m_workflow&&m_workflow->isRunning() &&
           (m_workflow->step()==FieldWorkflowStep::CaptureMaster||m_workflow->step()==FieldWorkflowStep::CaptureTerminal))
            m_workflow->operationFailed(QStringLiteral("抓包失败：%1").arg(e));
    });
    connect(m_capCtrl,&PacketCaptureController::captureStarted,this,[this]{
        m_lastCaptureStats=CaptureStats{};
        if(routerSerialMode()){
            setCaptureState(QStringLiteral("串口文本抓包运行中，报文实时显示"),LayerState::Normal);
            if(m_captureNoTrafficTimer)m_captureNoTrafficTimer->stop();
        }else{
            updateCaptureActivityState(QStringLiteral("当前暂无匹配流量"),LayerState::Normal);
            if(m_captureNoTrafficTimer)m_captureNoTrafficTimer->start();
        }
        statusBar()->showMessage(routerSerialMode()?QStringLiteral("正在通过串口实时抓包"):QStringLiteral("正在实时抓包"));updateConnectionUi();
        if(m_workflow&&m_workflow->isRunning()&&m_workflowCaptureTimer&&!m_workflowCaptureTimer->isActive() &&
           (m_workflow->step()==FieldWorkflowStep::CaptureMaster||m_workflow->step()==FieldWorkflowStep::CaptureTerminal)){
            const FieldDiagnosticConfig cfg=currentFieldConfig();
            const int seconds=(m_workflow->step()==FieldWorkflowStep::CaptureMaster && cfg.masterRole==EndpointRole::Client)
                ?qMax(ui->spinAutoCaptureSeconds->value(),cfg.expectedConnectionSeconds)
                :ui->spinAutoCaptureSeconds->value();
            m_workflowCaptureTimer->start(seconds*1000);
        }
    });
    connect(m_capCtrl,&PacketCaptureController::captureStopped,this,[this]{
        if(m_captureNoTrafficTimer)m_captureNoTrafficTimer->stop();
        if(m_protocolRefreshTimer)m_protocolRefreshTimer->stop();
        if(!m_tcpReassembler.directions().isEmpty())rebuildProtocolEvidenceFromStreams();
        setCaptureState(QStringLiteral("已停止"),LayerState::Unknown);
        statusBar()->showMessage("抓包已停止");
        renderFieldDiagnosis();updateConnectionUi();
        if(m_workflow&&m_workflow->isRunning()){
            if(m_workflow->step()==FieldWorkflowStep::CaptureMaster){
                if(routerSerialMode()){
                    log(QStringLiteral("一键诊断：主站抓包完成，串口控制台已恢复，继续终端阶段"));
                    m_workflow->masterCaptureCompleted();
                }else{
                    m_waitingCaptureReconnectForWorkflow=true;
                    log(QStringLiteral("一键诊断：主站抓包完成，正在重建抓包Telnet会话供终端阶段使用"));
                }
                return;
            }
            if(m_workflow->step()==FieldWorkflowStep::CaptureTerminal){m_workflow->terminalCaptureCompleted();return;}
        }
    });

    connect(m_offline,&OfflinePcapController::loaded,this,[this](const QString& source,int count,const PcapGlobalHeaderInfo& h){
        const QString name=source.isEmpty()?QStringLiteral("内存 PCAP"):QFileInfo(source).fileName();
        ui->labelOfflinePcap->setText(QStringLiteral("%1 | %2 包 | LinkType %3").arg(name).arg(count).arg(h.linkType));
        ui->btnReplayPcap->setEnabled(m_offline->replayAvailable());
        ui->btnReplayPcap->setToolTip(m_offline->replayAvailable()?QStringLiteral("按选择的速度重新回放已导入PCAP"):QStringLiteral("大文件采用流式导入，不缓存整包数据；当前结果已直接显示，如需回放请先裁剪PCAP"));
        statusBar()->showMessage(QStringLiteral("PCAP 已导入并分析：%1 个包").arg(count),5000);
    });
    connect(m_offline,&OfflinePcapController::loadProgress,this,[this](qint64 done,qint64 total,int packets){
        const int percent=total>0?int((done*100)/total):0;
        statusBar()->showMessage(QStringLiteral("正在读取PCAP：%1% · 已解析 %2 包").arg(percent).arg(packets));
    });
    connect(m_offline,&OfflinePcapController::packetReady,this,&MainWindow::appendPacket);
    connect(m_offline,&OfflinePcapController::statsUpdated,this,&MainWindow::updateStats);
    connect(m_offline,&OfflinePcapController::errorOccurred,this,[this](const QString& e){log("离线抓包: "+e);});
    connect(m_offline,&OfflinePcapController::replayStarted,this,[this]{statusBar()->showMessage("正在回放 PCAP");ui->mainTabs->setCurrentWidget(ui->tabRealtimeCapture);});
    connect(m_offline,&OfflinePcapController::replayFinished,this,[this]{statusBar()->showMessage("PCAP 回放完成",5000);renderFieldDiagnosis();});
    connect(m_offline,&OfflinePcapController::replayStopped,this,[this]{statusBar()->showMessage("PCAP 回放已停止",3000);});

    connect(m_control,&TelnetClient::errorOccurred,this,[this](const QString& e){
        log(QStringLiteral("控制连接: ")+e);
        if(m_routerConnectInProgress && !m_routerDisconnectRequested){
            abortRouterConnectionAttempt(QStringLiteral("控制连接失败：%1").arg(e));
            return;
        }
        if(routerSerialMode() && !m_control->isConnected())ui->labelConnectionState->setText(QStringLiteral("串口连接失败：%1").arg(e));
        updateConnectionUi();
    });
    connect(m_capture,&TelnetClient::errorOccurred,this,[this](const QString& e){
        log("抓包连接: "+e);
        if(m_routerConnectInProgress && !m_routerDisconnectRequested){
            abortRouterConnectionAttempt(QStringLiteral("抓包连接失败：%1").arg(e));
            return;
        }
        if(m_waitingCaptureReconnectForWorkflow && m_workflow&&m_workflow->isRunning()){
            m_waitingCaptureReconnectForWorkflow=false;
            m_workflow->operationFailed(QStringLiteral("抓包连接重建失败：%1").arg(e));
        }
    });
    connect(m_control,&TelnetClient::connected,this,[this]{
        if(m_control->isSerialTransport()){
            const QString port=ui->comboPcSerialPort->currentData().toString();
            ui->labelConnectionState->setText(QStringLiteral("串口 %1 已打开，正在登录").arg(port));
            log(QStringLiteral("路由器串口 %1 已打开，已发送回车，正在登录").arg(port));
        }else{
            ui->labelConnectionState->setText(QStringLiteral("控制连接TCP已连接，正在登录"));
            log(QStringLiteral("控制连接 TCP 已连接，正在登录"));
        }
        m_control->login(ui->editUser->text(),ui->editPassword->text());
    });
    connect(m_capture,&TelnetClient::connected,this,[this]{
        log("抓包连接 TCP 已连接，正在登录");
        m_capture->setMode(TelnetMode::CommandMode);
        m_capture->login(ui->editUser->text(),ui->editPassword->text());
    });
    connect(m_control,&TelnetClient::loginSucceeded,this,[this]{
        m_controlLoggedIn=true;
        if(m_control->isSerialTransport()){
            const QString port=ui->comboPcSerialPort->currentData().toString();
            ui->labelConnectionState->setText(QStringLiteral("已通过串口 %1 登录路由后台").arg(port));
            log(QStringLiteral("串口控制台 登录成功：%1").arg(port));
        }else{
            ui->labelConnectionState->setText(QStringLiteral("已连接并登录：%1:%2").arg(ui->editHost->text().trimmed()).arg(ui->spinPort->value()));
            log(QStringLiteral("控制连接 登录成功"));
            saveConnectionHistory();
        }
        if(routerSerialMode() || m_captureLoggedIn){
            m_routerConnectInProgress=false;
            m_routerConnectionFailureMessage.clear();
        }
        ui->labelAutoDetectStatus->setText(QStringLiteral("连接成功，等待手工诊断；不会自动检测 WAN/SIM/模组"));
        updateConnectionUi();
    });
    connect(m_capture,&TelnetClient::loginSucceeded,this,[this]{
        m_captureLoggedIn=true;log("抓包连接 登录成功");
        if(m_controlLoggedIn){
            ui->labelConnectionState->setText(QStringLiteral("已连接：控制/抓包会话均已登录"));
            m_routerConnectInProgress=false;
            m_routerConnectionFailureMessage.clear();
        }
        updateConnectionUi();
        if(m_waitingCaptureReconnectForWorkflow && m_workflow&&m_workflow->isRunning() && m_workflow->step()==FieldWorkflowStep::CaptureMaster){
            m_waitingCaptureReconnectForWorkflow=false;
            m_workflow->masterCaptureCompleted();
        }
    });
    connect(m_control,&TelnetClient::loginFailed,this,[this](const QString& e){
        m_controlLoggedIn=false;
        log("控制连接 登录失败: "+e);
        abortRouterConnectionAttempt(QStringLiteral("控制连接登录失败：%1").arg(e));
    });
    connect(m_capture,&TelnetClient::loginFailed,this,[this](const QString& e){
        m_captureLoggedIn=false;log("抓包连接 登录失败: "+e);
        if(m_routerConnectInProgress){
            abortRouterConnectionAttempt(QStringLiteral("抓包连接登录失败：%1").arg(e));
            return;
        }
        updateConnectionUi();
        if(m_waitingCaptureReconnectForWorkflow && m_workflow&&m_workflow->isRunning()){
            m_waitingCaptureReconnectForWorkflow=false;
            m_workflow->operationFailed(QStringLiteral("抓包连接重建登录失败：%1").arg(e));
        }
    });
    connect(m_control,&TelnetClient::disconnected,this,[this]{
        m_controlLoggedIn=false;
        if(m_routerConnectInProgress && !m_routerDisconnectRequested){
            abortRouterConnectionAttempt(QStringLiteral("控制连接在登录完成前已断开"));
            return;
        }
        if(!m_routerConnectionFailureMessage.isEmpty())ui->labelConnectionState->setText(m_routerConnectionFailureMessage);
        else ui->labelConnectionState->setText(QStringLiteral("控制连接已断开"));
        log(QStringLiteral("控制连接已断开"));updateConnectionUi();
    });
    connect(m_capture,&TelnetClient::disconnected,this,[this]{
        m_captureLoggedIn=false;log(QStringLiteral("抓包连接已断开"));
        if(m_routerConnectInProgress && !m_routerDisconnectRequested){
            abortRouterConnectionAttempt(QStringLiteral("抓包连接在登录完成前已断开"));
            return;
        }
        if(!m_routerConnectionFailureMessage.isEmpty())ui->labelConnectionState->setText(m_routerConnectionFailureMessage);
        updateConnectionUi();
        if(!routerSerialMode() && !m_routerDisconnectRequested && m_controlLoggedIn){
            QTimer::singleShot(180,this,[this]{
                if(!routerSerialMode() && !m_routerDisconnectRequested && m_controlLoggedIn && !m_capture->isConnected()){
                    log(QStringLiteral("正在自动重建抓包Telnet连接"));
                    loginClient(m_capture,QStringLiteral("抓包连接"));
                }
            });
        }
    });

    connect(m_moduleLog,&TelnetClient::connected,this,[this]{
        log(QStringLiteral("模块日志连接 TCP 已连接，正在登录"));
        m_moduleLog->setMode(TelnetMode::CommandMode);
        m_moduleLog->login(ui->editUser->text(),ui->editPassword->text());
    });
    connect(m_moduleLog,&TelnetClient::loginSucceeded,this,[this]{
        log(QStringLiteral("模组日志连接 登录成功，检查 debuglog_enable"));
        m_moduleLogSetupState=ModuleLogSetupState::CheckingDebug;
        m_moduleLog->executeCommand(QStringLiteral("nvram get debuglog_enable"),3000);
    });
    connect(m_moduleLog,&TelnetClient::commandFinished,this,[this](const QString& cmd,const QString& out){
        auto outputHasScalar=[](const QString& output,const QString& expected){
            const QStringList lines=output.split(QRegularExpression(QStringLiteral("[\r\n]+")),Qt::SkipEmptyParts);
            for(const QString& line:lines)if(line.trimmed()==expected)return true;
            return false;
        };
        if(m_moduleLogSetupState==ModuleLogSetupState::CheckingDebug && cmd==QStringLiteral("nvram get debuglog_enable")){
            if(outputHasScalar(out,QStringLiteral("1"))){
                m_moduleLogSetupState=ModuleLogSetupState::CheckingSyslog;
                m_moduleLog->executeCommand(QStringLiteral("nvram get syslogd_enable"),3000);
            }else{
                log(QStringLiteral("系统日志未开启，正在设置 debuglog_enable=1"));
                m_moduleLogSetupState=ModuleLogSetupState::SettingDebug;
                m_moduleLog->executeCommand(QStringLiteral("nvram set debuglog_enable=1"),3000);
            }
            return;
        }
        if(m_moduleLogSetupState==ModuleLogSetupState::SettingDebug && cmd==QStringLiteral("nvram set debuglog_enable=1")){
            m_moduleLogSetupState=ModuleLogSetupState::CommitDebug;
            m_moduleLog->executeCommand(QStringLiteral("nvram commit"),5000);
            return;
        }
        if(m_moduleLogSetupState==ModuleLogSetupState::CommitDebug && cmd==QStringLiteral("nvram commit")){
            m_moduleLogSetupState=ModuleLogSetupState::CheckingSyslog;
            m_moduleLog->executeCommand(QStringLiteral("nvram get syslogd_enable"),3000);
            return;
        }
        if(m_moduleLogSetupState==ModuleLogSetupState::CheckingSyslog && cmd==QStringLiteral("nvram get syslogd_enable")){
            if(outputHasScalar(out,QStringLiteral("3"))){
                log(QStringLiteral("系统日志已启用且输出到网页/网口Telnet，开始 tail /tmp/.systemlog -f"));
                m_moduleLogSetupState=ModuleLogSetupState::Tailing;
                m_moduleLog->executeCommand(QStringLiteral("tail /tmp/.systemlog -f"),24*60*60*1000);
            }else{
                log(QStringLiteral("正在设置 syslogd_enable=3，以便网口Telnet读取 /tmp/.systemlog"));
                m_moduleLogSetupState=ModuleLogSetupState::SettingSyslog;
                m_moduleLog->executeCommand(QStringLiteral("nvram set syslogd_enable=3"),3000);
            }
            return;
        }
        if(m_moduleLogSetupState==ModuleLogSetupState::SettingSyslog && cmd==QStringLiteral("nvram set syslogd_enable=3")){
            m_moduleLogSetupState=ModuleLogSetupState::CommitSyslog;
            m_moduleLog->executeCommand(QStringLiteral("nvram commit"),5000);
            return;
        }
        if(m_moduleLogSetupState==ModuleLogSetupState::CommitSyslog && cmd==QStringLiteral("nvram commit")){
            log(QStringLiteral("系统日志配置已保存，开始 tail /tmp/.systemlog -f"));
            m_moduleLogSetupState=ModuleLogSetupState::Tailing;
            m_moduleLog->executeCommand(QStringLiteral("tail /tmp/.systemlog -f"),24*60*60*1000);
        }
    });
    connect(m_moduleLog,&TelnetClient::visibleTextReceived,this,[this](const QString& text){
        if(m_moduleLogSetupState==ModuleLogSetupState::Tailing)processBackgroundModuleLogText(text);
    });
    connect(m_moduleLog,&TelnetClient::errorOccurred,this,[this](const QString& e){
        log(QStringLiteral("模块日志连接: %1").arg(e));
    });
    connect(m_moduleLog,&TelnetClient::disconnected,this,[this]{
        m_moduleLogSetupState=ModuleLogSetupState::Idle;
        if(!m_routerDisconnectRequested && m_controlLoggedIn)
            log(QStringLiteral("模块日志连接已断开，可通过重新连接路由器恢复实时状态提取"));
    });

    loadConnectionHistory();
    loadFieldHistory();
    refreshSerialPorts();
    updateRouterConnectionModeUi();
    ui->editMasterIp->setToolTip(QStringLiteral("主站可能禁用ICMP Ping；Ping仅作为辅助证据，一键诊断会继续抓取业务端口TCP并以TCP会话状态为主判断"));
    ui->spinMasterPort->setToolTip(QStringLiteral("主站业务TCP端口；当主站禁Ping时，SYN/SYN-ACK/RST和业务数据是主要诊断依据"));
    updateTerminalTransportUi();
    updateCaptureModeUi();
    updateConnectionUi();
    renderFieldDiagnosis();
}


void MainWindow::setupDetachableTabs()
{
    const QList<QTabWidget*> tabs={ui->mainTabs,ui->diagnosisDetailTabs,ui->packetDetailTabs};
    for(QTabWidget* tab:tabs){
        if(!tab)continue;
        tab->setMovable(true);
        auto* manager=new DetachableTabWidget(tab,this);
        m_detachableTabManagers.append(manager);
    }
}

void MainWindow::setupResizableWorkspace()
{
    // Data-heavy areas expand with the main window; no hard maximum height keeps
    // useful space trapped when the user maximizes the application.
    ui->tableInterfaces->setMaximumHeight(QWIDGETSIZE_MAX);
    ui->txtPingResult->setMaximumHeight(QWIDGETSIZE_MAX);
    ui->txtStats->setMaximumWidth(QWIDGETSIZE_MAX);
    ui->txtStats->setMinimumWidth(180);
    ui->tablePackets->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    ui->packetDetailPane->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    ui->tableLayerStatus->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    ui->diagnosisDetailTabs->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);

    // The packet list and statistics used to be a fixed horizontal layout.
    // Convert it into a real splitter so either side can be enlarged on demand.
    auto* packetStatsSplitter=new QSplitter(Qt::Horizontal,ui->packetTopPane);
    packetStatsSplitter->setObjectName(QStringLiteral("packetStatsSplitter"));
    packetStatsSplitter->setHandleWidth(6);
    packetStatsSplitter->setChildrenCollapsible(true);
    ui->packetTopLayout->removeWidget(ui->tablePackets);
    ui->packetTopLayout->removeWidget(ui->txtStats);
    packetStatsSplitter->addWidget(ui->tablePackets);
    packetStatsSplitter->addWidget(ui->txtStats);
    packetStatsSplitter->setStretchFactor(0,5);
    packetStatsSplitter->setStretchFactor(1,2);
    ui->packetTopLayout->addWidget(packetStatsSplitter);

    const auto restoreSplitter=[](QSplitter* splitter,const QString& key,const QList<int>& fallback){
        if(!splitter)return;
        QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
        const QByteArray state=settings.value(key).toByteArray();
        if(state.isEmpty() || !splitter->restoreState(state))splitter->setSizes(fallback);
        QObject::connect(splitter,&QSplitter::splitterMoved,splitter,[splitter,key](int,int){
            QSettings s(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
            s.setValue(key,splitter->saveState());
        });
    };
    restoreSplitter(packetStatsSplitter,QStringLiteral("workspace/packetStatsSplitter"),{900,260});
    packetStatsSplitter->setOrientation(width()<1000?Qt::Vertical:Qt::Horizontal);
    restoreSplitter(ui->packetVerticalSplitter,QStringLiteral("workspace/packetVerticalSplitter"),{560,360});
    restoreSplitter(ui->diagnosisSplitter,QStringLiteral("workspace/diagnosisSplitter"),{520,760});
    restoreSplitter(ui->mainVerticalSplitter,QStringLiteral("workspace/mainVerticalSplitter"),{760,180});

    // Whole work panels can be dragged out as top-level windows. Individual
    // packet/detail tabs remain detachable through DetachableTabWidget as well.
    auto addPanel=[this](QWidget* panel,const QString& title,const QString& key){
        auto* manager=new DetachablePanelManager(panel,title,key,this);
        m_detachablePanelManagers.append(manager);
        return manager;
    };
    auto* capturePacketsManager=addPanel(ui->packetTopPane,QStringLiteral("实时抓包：报文与统计"),QStringLiteral("capturePackets"));
    m_newCaptureWindowButton=ui->btnNewCaptureWindow;
    m_newCaptureWindowButton->setText(QStringLiteral("+ 新建抓包窗口"));
    m_newCaptureWindowButton->setToolTip(QStringLiteral("打开独立抓包窗口，可选择不同接口和过滤条件并行观察"));
    m_newCaptureWindowButton->setProperty("role","quiet");
    capturePacketsManager->addHeaderWidget(m_newCaptureWindowButton);
    connect(m_newCaptureWindowButton,&QPushButton::clicked,this,[this]{
        createCaptureSessionWindow(QStringLiteral("实时抓包 %1").arg(m_captureSessions.size()+1),captureInterfaceText(),ui->editFilter->text().trimmed(),false);
    });
    addPanel(ui->packetDetailPane,QStringLiteral("实时抓包：包详情"),QStringLiteral("captureDetails"));
    addPanel(ui->diagnosisDetailTabs,QStringLiteral("现场诊断：详情与报告"),QStringLiteral("diagnosisDetails"));
    addPanel(ui->tableLayerStatus,QStringLiteral("现场诊断：层级列表"),QStringLiteral("diagnosisLayers"));
    m_pingPanelManager=addPanel(ui->groupPingResult,QStringLiteral("Ping 实时结果"),QStringLiteral("pingResult"));
    m_deviceDetailsPanelManager=addPanel(ui->deviceDetailsPanel,QStringLiteral("网口详情"),QStringLiteral("deviceInterfaces"));
    m_runtimeLogPanelManager=addPanel(ui->groupRuntimeLog,QStringLiteral("实时运行日志"),QStringLiteral("runtimeLog"));
}



void MainWindow::setupCaptureInterfaceSelector()
{
    if(m_captureIfacePanel)return;

    // Batch45 defines the editable interface selector and refresh button in
    // MainWindow.ui. Reuse those widgets instead of creating a second copy.
    // This keeps UIC and MainWindow.cpp in sync and lets responsive reflow move
    // the pair as one unit without referencing the removed editIface control.
    m_captureIfaceCombo=ui->comboCaptureInterface;
    m_refreshCaptureIfaces=ui->btnRefreshCaptureInterfaces;
    m_captureIfacePanel=new QWidget(ui->groupCaptureControl);
    m_captureIfacePanel->setObjectName(QStringLiteral("captureInterfacePanel"));
    auto* row=new QHBoxLayout(m_captureIfacePanel);
    row->setContentsMargins(0,0,0,0);row->setSpacing(6);

    m_captureIfaceCombo->setEditable(true);
    m_captureIfaceCombo->setInsertPolicy(QComboBox::NoInsert);
    m_captureIfaceCombo->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Fixed);
    m_captureIfaceCombo->lineEdit()->setPlaceholderText(QStringLiteral("下拉仅显示 ifconfig 实际接口（UP）；any=所有接口；也可手工输入 tun0 / usb0"));
    m_refreshCaptureIfaces->setToolTip(QStringLiteral("刷新只读取普通 ifconfig 的 UP 接口；any 是 tcpdump 的所有接口特殊项"));

    // Adding existing UI widgets to the panel removes them from their original
    // grid cells. reflowResponsiveLayout() will then place this panel.
    row->addWidget(m_captureIfaceCombo,1);
    row->addWidget(m_refreshCaptureIfaces);
    if(ui->gridCaptureControl)ui->gridCaptureControl->addWidget(m_captureIfacePanel,0,3,1,2);

    rebuildCaptureInterfaceChoices();
    connect(m_refreshCaptureIfaces,&QPushButton::clicked,this,&MainWindow::refreshCaptureInterfaces);
}

QString MainWindow::captureInterfaceText() const
{
    return m_captureIfaceCombo?m_captureIfaceCombo->currentText().trimmed():QString();
}

void MainWindow::setCaptureInterfaceText(const QString& iface)
{
    if(!m_captureIfaceCombo)return;
    const QSignalBlocker blocker(m_captureIfaceCombo);
    m_captureIfaceCombo->setEditText(iface.trimmed());
}

QStringList MainWindow::captureInterfaceChoices() const
{
    QStringList result;
    if(m_captureIfaceCombo)
        for(int i=0;i<m_captureIfaceCombo->count();++i){const QString v=m_captureIfaceCombo->itemText(i).trimmed();if(!v.isEmpty()&&!result.contains(v))result<<v;}
    return result;
}

void MainWindow::rebuildCaptureInterfaceChoices()
{
    if(!m_captureIfaceCombo)return;
    const QString current=captureInterfaceText();
    QStringList names;
    names<<QStringLiteral("any");
    for(const auto& info:m_discoveredInterfaces)if(info.up && !info.name.trimmed().isEmpty()&&!names.contains(info.name.trimmed()))names<<info.name.trimmed();
    const QSignalBlocker blocker(m_captureIfaceCombo);
    m_captureIfaceCombo->clear();
    m_captureIfaceCombo->addItems(names);
    m_captureIfaceCombo->setEditText(current);
    m_captureIfaceCombo->setToolTip(QStringLiteral("除 any 外，下拉只显示普通 ifconfig 返回且状态为 UP 的接口；any 表示 tcpdump 抓取所有接口。手工抓包选择不会改变WAN诊断结果。"));
}

void MainWindow::refreshCaptureInterfaces()
{
    if(!m_controlLoggedIn || !m_control || !m_control->isConnected()){
        rebuildCaptureInterfaceChoices();
        statusBar()->showMessage(QStringLiteral("请先连接路由器；当前仍可手工输入抓包接口"),5000);
        return;
    }
    if(controlCommandBusy()){
        statusBar()->showMessage(QStringLiteral("控制通道忙，稍后再刷新接口；也可以直接手工输入 tun0 等接口"),5000);
        return;
    }
    ui->labelAutoDetectStatus->setText(QStringLiteral("正在读取 ifconfig 接口列表..."));
    const QString command=QStringLiteral("ifconfig 2>/dev/null");
    m_control->executeCommand(command,5000);
}

void MainWindow::setupSerialCaptureWorkspace()
{
    if(!ui || !ui->packetDetailTabs || m_serialCommunicationLog)return;
    m_serialCommunicationLog=new QPlainTextEdit(ui->packetDetailTabs);
    m_serialCommunicationLog->setObjectName(QStringLiteral("txtSerialCommunication"));
    m_serialCommunicationLog->setReadOnly(true);
    m_serialCommunicationLog->setPlaceholderText(QStringLiteral("终端通讯选择串口时，这里分类显示串口控制台/串口相关日志；若路由器当前不是串口控制台连接，会明确提示无直接串口流。"));
    m_serialNetworkTimeline=new QPlainTextEdit(ui->packetDetailTabs);
    m_serialNetworkTimeline->setObjectName(QStringLiteral("txtSerialNetworkTimeline"));
    m_serialNetworkTimeline->setReadOnly(true);
    m_serialNetworkTimeline->setPlaceholderText(QStringLiteral("按时间并列显示串口日志与网络报文；仅表示时间邻近，不自动断言属于同一业务帧。"));
    m_serialCommunicationTab=ui->packetDetailTabs->addTab(m_serialCommunicationLog,QStringLiteral("串口通信"));
    m_serialTimelineTab=ui->packetDetailTabs->addTab(m_serialNetworkTimeline,QStringLiteral("串口与网络时间线"));
    ui->packetDetailTabs->setTabVisible(m_serialCommunicationTab,false);
    ui->packetDetailTabs->setTabVisible(m_serialTimelineTab,false);
}

void MainWindow::appendCaptureTimeline(const QString& source,const QString& detail)
{
    if(!m_serialNetworkTimeline || ui->comboTerminalTransport->currentIndex()==0)return;
    m_serialNetworkTimeline->appendPlainText(QStringLiteral("%1  [%2]  %3").arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),source,detail));
}

void MainWindow::appendSerialConsoleText(const QString& text)
{
    if(!m_serialCommunicationLog || ui->comboTerminalTransport->currentIndex()==0)return;
    const QString cleaned=text.trimmed();if(cleaned.isEmpty())return;
    const QString stamp=QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
    m_serialCommunicationLog->appendPlainText(QStringLiteral("%1  %2").arg(stamp,cleaned));
    appendCaptureTimeline(QStringLiteral("串口"),cleaned.left(240));
}

CaptureSessionWidget* MainWindow::createCaptureSessionWindow(const QString& title,const QString& iface,const QString& filter,bool autoStart,bool autoRefreshInterfaces)
{
    if(!m_controlLoggedIn || !m_control || !m_control->isConnected()){
        statusBar()->showMessage(QStringLiteral("请先连接并登录路由器，再新建抓包窗口"),5000);
        return nullptr;
    }
    CaptureSessionConnectionParams params;
    params.serialShared=routerSerialMode();
    if(params.serialShared){
        params.sharedControl=m_control;
    }else{
        params.host=ui->editHost->text().trimmed();
        params.port=quint16(ui->spinPort->value());
        params.user=ui->editUser->text();
        params.password=ui->editPassword->text();
    }
    params.interfaces=captureInterfaceChoices();
    params.autoRefreshInterfaces=autoRefreshInterfaces;
    auto* session=new CaptureSessionWidget(title,params,nullptr);
    session->setCaptureSpec(iface,filter);
    session->setStartGuard([this,session]()->QString{
        if(!routerSerialMode())return {};
        if(m_capCtrl && m_capCtrl->isRunning())return QStringLiteral("串口连接模式同一时间只能运行 1 个实时抓包");
        for(CaptureSessionWidget* other:m_captureSessions){
            if(other && other!=session && other->isRunning())return QStringLiteral("串口连接模式同一时间只能运行 1 个实时抓包");
        }
        return {};
    });
    m_captureSessions.append(session);
    connect(session,&QObject::destroyed,this,[this,session]{m_captureSessions.removeAll(session);});
    connect(session,&CaptureSessionWidget::captureSessionFailed,this,[this,title](const QString& reason){
        log(QStringLiteral("%1失败：%2").arg(title,reason));
    });
    session->show();
    session->raise();
    if(autoStart)QTimer::singleShot(0,session,&CaptureSessionWidget::startCapture);
    return session;
}

MainWindow::~MainWindow()
{
    // Reattach floating pages/panels while the designer widgets still exist.
    // QObject child destruction happens after this destructor body, which would
    // otherwise leave the managers holding pointers to widgets already deleted by ui.
    qDeleteAll(m_detachablePanelManagers);m_detachablePanelManagers.clear();
    qDeleteAll(m_detachableTabManagers);m_detachableTabManagers.clear();
    delete ui;
}

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QMainWindow::resizeEvent(event);
    reflowResponsiveLayout(event?event->size().width():width());
}

void MainWindow::reflowResponsiveLayout(int width)
{
    if(!ui || !ui->centralwidget)return;
    enum class ResponsiveMode { Wide, Compact, Narrow };
    const ResponsiveMode mode=width>=1440?ResponsiveMode::Wide:(width>=1000?ResponsiveMode::Compact:ResponsiveMode::Narrow);
    const QString responsiveLayoutMode=mode==ResponsiveMode::Wide?QStringLiteral("wide"):(mode==ResponsiveMode::Compact?QStringLiteral("compact"):QStringLiteral("narrow"));
    if(ui->centralwidget->property("responsiveLayoutMode").toString()==responsiveLayoutMode)return;
    ui->centralwidget->setProperty("responsiveLayoutMode",responsiveLayoutMode);
    const bool narrow=mode==ResponsiveMode::Narrow;
    const bool compact=mode!=ResponsiveMode::Wide;

    auto* connectionCollapse=ui->groupConnection->findChild<QPushButton*>(QStringLiteral("btnToggleRouterConnectionCollapsed"));
    auto* compactConnectionBar=ui->groupConnection->findChild<QWidget*>(QStringLiteral("compactConnectionBar"));

    for(DetachablePanelManager* manager:m_detachablePanelManagers)if(manager)manager->setCompactHeader(compact);
    const QList<QSpinBox*> compactSpins={ui->spinMasterPort,ui->spinTerminalPort,ui->spinAutoCaptureSeconds,ui->spinExpectedConnectionSeconds};
    for(QSpinBox* spin:compactSpins)if(spin)spin->setButtonSymbols(compact?QAbstractSpinBox::NoButtons:QAbstractSpinBox::UpDownArrows);
    ui->spinMasterPort->setMinimumWidth(compact?78:100);
    ui->spinMasterPort->setMaximumWidth(compact?96:110);
    ui->spinTerminalPort->setMinimumWidth(compact?78:100);
    ui->spinTerminalPort->setMaximumWidth(compact?96:110);

    // Connection area: the first step can enter the router backend through network Telnet
    // or a PC serial console. Both paths share the same credentials and post-login workflow.
    clearLayoutItems(ui->gridConnection);
    if(narrow){
        ui->gridConnection->addWidget(ui->labelRouterConnectionMode,0,0);ui->gridConnection->addWidget(ui->comboRouterConnectionMode,0,1,1,5);
        ui->gridConnection->addWidget(ui->labelHost,1,0);ui->gridConnection->addWidget(ui->editHost,1,1,1,3);
        ui->gridConnection->addWidget(ui->labelPort,1,4);ui->gridConnection->addWidget(ui->spinPort,1,5);
        ui->gridConnection->addWidget(ui->serialSettingsPanel,1,0,1,6);
        ui->gridConnection->addWidget(ui->labelUser,2,0);ui->gridConnection->addWidget(ui->editUser,2,1,1,2);
        ui->gridConnection->addWidget(ui->labelPassword,2,3);ui->gridConnection->addWidget(ui->editPassword,2,4,1,2);
        ui->gridConnection->addWidget(ui->btnConnect,3,0);ui->gridConnection->addWidget(ui->btnDisconnect,3,1);
        ui->gridConnection->addWidget(ui->labelConnectionStateTitle,3,2);ui->gridConnection->addWidget(ui->labelConnectionState,3,3,1,3);
        ui->gridConnection->addWidget(ui->labelDefaultAccount,4,0,1,2);ui->gridConnection->addWidget(ui->labelHistory,4,2);ui->gridConnection->addWidget(ui->comboConnectionHistory,4,3,1,3);
        if(connectionCollapse)ui->gridConnection->addWidget(connectionCollapse,5,4,1,2);
        if(compactConnectionBar)ui->gridConnection->addWidget(compactConnectionBar,6,0,1,6);
    }else if(compact){
        ui->gridConnection->addWidget(ui->labelRouterConnectionMode,0,0);ui->gridConnection->addWidget(ui->comboRouterConnectionMode,0,1,1,2);
        ui->gridConnection->addWidget(ui->btnConnect,0,6);ui->gridConnection->addWidget(ui->btnDisconnect,0,7);
        ui->gridConnection->addWidget(ui->labelHost,1,0);ui->gridConnection->addWidget(ui->editHost,1,1,1,3);ui->gridConnection->addWidget(ui->labelPort,1,4);ui->gridConnection->addWidget(ui->spinPort,1,5);
        ui->gridConnection->addWidget(ui->serialSettingsPanel,1,0,1,8);
        ui->gridConnection->addWidget(ui->labelUser,2,0);ui->gridConnection->addWidget(ui->editUser,2,1,1,3);ui->gridConnection->addWidget(ui->labelPassword,2,4);ui->gridConnection->addWidget(ui->editPassword,2,5,1,3);
        ui->gridConnection->addWidget(ui->labelDefaultAccount,3,0,1,2);ui->gridConnection->addWidget(ui->labelHistory,3,2);ui->gridConnection->addWidget(ui->comboConnectionHistory,3,3,1,3);if(connectionCollapse)ui->gridConnection->addWidget(connectionCollapse,3,6,1,2);
        ui->gridConnection->addWidget(ui->labelConnectionStateTitle,4,0);ui->gridConnection->addWidget(ui->labelConnectionState,4,1,1,7);
        if(compactConnectionBar)ui->gridConnection->addWidget(compactConnectionBar,5,0,1,8);
    }else{
        ui->gridConnection->addWidget(ui->labelRouterConnectionMode,0,0);ui->gridConnection->addWidget(ui->comboRouterConnectionMode,0,1);
        ui->gridConnection->addWidget(ui->labelHost,0,2);ui->gridConnection->addWidget(ui->editHost,0,3);ui->gridConnection->addWidget(ui->labelPort,0,4);ui->gridConnection->addWidget(ui->spinPort,0,5);
        ui->gridConnection->addWidget(ui->serialSettingsPanel,0,2,1,6);
        ui->gridConnection->addWidget(ui->btnConnect,0,8);ui->gridConnection->addWidget(ui->btnDisconnect,0,9);
        ui->gridConnection->addWidget(ui->labelUser,1,0);ui->gridConnection->addWidget(ui->editUser,1,1,1,2);ui->gridConnection->addWidget(ui->labelPassword,1,3);ui->gridConnection->addWidget(ui->editPassword,1,4,1,2);
        ui->gridConnection->addWidget(ui->labelDefaultAccount,1,6);ui->gridConnection->addWidget(ui->labelHistory,1,7);ui->gridConnection->addWidget(ui->comboConnectionHistory,1,8,1,3);
        ui->gridConnection->addWidget(ui->labelConnectionStateTitle,2,0);ui->gridConnection->addWidget(ui->labelConnectionState,2,1,1,10);
        if(connectionCollapse)ui->gridConnection->addWidget(connectionCollapse,0,10);
        if(compactConnectionBar)ui->gridConnection->addWidget(compactConnectionBar,3,0,1,12);
    }
    ui->labelConnectionState->setWordWrap(true);
    ui->labelConnectionState->setMinimumWidth(0);
    // Reapply collapsed visibility after reflow; connection-mode-specific controls remain exclusive.
    setRouterConnectionCollapsed(ui->groupConnection->property("rc13Collapsed").toBool());

    // Status cards: 6-wide, 3x2 or 2x3 depending on available width.
    clearLayoutItems(ui->deviceCardsLayout);
    for(int i=0;i<8;++i)ui->deviceCardsLayout->setColumnStretch(i,0);
    const QList<QLabel*> cards={ui->labelCardWan,ui->labelCardModule,ui->labelCardSim,ui->labelCardRegistration,ui->labelCardWanIp,ui->labelCardSignal};
    const int cardColumns=narrow?2:(width<1180?3:6);
    for(int i=0;i<cards.size();++i)ui->deviceCardsLayout->addWidget(cards.at(i),i/cardColumns,i%cardColumns);
    const int buttonRow=(cards.size()+cardColumns-1)/cardColumns;
    ui->deviceCardsLayout->addWidget(ui->btnToggleDeviceDetails,buttonRow,cardColumns-1,1,1,Qt::AlignRight);
    for(int i=0;i<cardColumns;++i)ui->deviceCardsLayout->setColumnStretch(i,1);

    // Field diagnosis inputs are always fully managed by the grid.  Older responsive
    // reflow left role/wait widgets unmanaged, so they kept stale geometry at 1280px.
    clearLayoutItems(ui->gridFieldInput);
    auto* fieldAdvanced=ui->groupFieldInput->findChild<QWidget*>(QStringLiteral("fieldAdvancedPanel"));
    auto* fieldAdvancedToggle=ui->groupFieldInput->findChild<QPushButton*>(QStringLiteral("btnToggleFieldAdvanced"));
    if(narrow){
        ui->gridFieldInput->addWidget(ui->labelMasterIp,0,0);ui->gridFieldInput->addWidget(ui->editMasterIp,0,1,1,3);
        ui->gridFieldInput->addWidget(ui->labelMasterPort,1,0);ui->gridFieldInput->addWidget(ui->spinMasterPort,1,1);ui->gridFieldInput->addWidget(ui->btnPingMaster,1,2,1,2);
        ui->gridFieldInput->addWidget(ui->labelTerminalTransport,2,0);ui->gridFieldInput->addWidget(ui->comboTerminalTransport,2,1,1,3);
        ui->gridFieldInput->addWidget(ui->labelTerminalIp,3,0);ui->gridFieldInput->addWidget(ui->editTerminalIp,3,1,1,3);
        ui->gridFieldInput->addWidget(ui->labelTerminalPort,4,0);ui->gridFieldInput->addWidget(ui->spinTerminalPort,4,1);ui->gridFieldInput->addLayout(ui->terminalActionLayout,4,2,1,2);
        ui->gridFieldInput->addWidget(ui->labelMasterRole,5,0);ui->gridFieldInput->addWidget(ui->comboMasterRole,5,1);ui->gridFieldInput->addWidget(ui->labelTerminalRole,5,2);ui->gridFieldInput->addWidget(ui->comboTerminalRole,5,3);
        if(fieldAdvancedToggle)ui->gridFieldInput->addWidget(fieldAdvancedToggle,6,0,1,2);
        ui->gridFieldInput->addWidget(ui->btnOneClickDiagnosis,6,2,1,2);
        if(fieldAdvanced)ui->gridFieldInput->addWidget(fieldAdvanced,7,0,1,4);
        ui->gridFieldInput->addWidget(ui->labelTerminalModeHint,8,0,1,4);ui->gridFieldInput->addWidget(ui->labelWorkflowState,9,0,1,4);
    }else if(compact){
        ui->gridFieldInput->addWidget(ui->labelMasterIp,0,0);ui->gridFieldInput->addWidget(ui->editMasterIp,0,1,1,2);ui->gridFieldInput->addWidget(ui->labelMasterPort,0,3);ui->gridFieldInput->addWidget(ui->spinMasterPort,0,4);ui->gridFieldInput->addWidget(ui->btnPingMaster,0,5);ui->gridFieldInput->addWidget(ui->btnOneClickDiagnosis,0,6);
        ui->gridFieldInput->addWidget(ui->labelTerminalTransport,1,0);ui->gridFieldInput->addWidget(ui->comboTerminalTransport,1,1);ui->gridFieldInput->addWidget(ui->labelTerminalIp,1,2);ui->gridFieldInput->addWidget(ui->editTerminalIp,1,3,1,2);ui->gridFieldInput->addWidget(ui->labelTerminalPort,1,5);ui->gridFieldInput->addWidget(ui->spinTerminalPort,1,6);ui->gridFieldInput->addLayout(ui->terminalActionLayout,1,7);
        ui->gridFieldInput->addWidget(ui->labelMasterRole,2,0);ui->gridFieldInput->addWidget(ui->comboMasterRole,2,1,1,2);ui->gridFieldInput->addWidget(ui->labelTerminalRole,2,3);ui->gridFieldInput->addWidget(ui->comboTerminalRole,2,4,1,2);
        if(fieldAdvancedToggle)ui->gridFieldInput->addWidget(fieldAdvancedToggle,2,6,1,2);
        if(fieldAdvanced)ui->gridFieldInput->addWidget(fieldAdvanced,3,0,1,8);
        ui->gridFieldInput->addWidget(ui->labelTerminalModeHint,4,0,1,6);ui->gridFieldInput->addWidget(ui->labelWorkflowState,4,6,1,2);
    }else{
        ui->gridFieldInput->addWidget(ui->labelMasterIp,0,0);ui->gridFieldInput->addWidget(ui->editMasterIp,0,1);ui->gridFieldInput->addWidget(ui->labelMasterPort,0,2);ui->gridFieldInput->addWidget(ui->spinMasterPort,0,3);ui->gridFieldInput->addWidget(ui->btnPingMaster,0,4);
        ui->gridFieldInput->addWidget(ui->btnOneClickDiagnosis,0,6);ui->gridFieldInput->addWidget(ui->btnCancelOneClick,0,7);
        ui->gridFieldInput->addWidget(ui->labelTerminalTransport,1,0);ui->gridFieldInput->addWidget(ui->comboTerminalTransport,1,1);ui->gridFieldInput->addWidget(ui->labelTerminalIp,1,2);ui->gridFieldInput->addWidget(ui->editTerminalIp,1,3);ui->gridFieldInput->addWidget(ui->labelTerminalPort,1,4);ui->gridFieldInput->addWidget(ui->spinTerminalPort,1,5);ui->gridFieldInput->addLayout(ui->terminalActionLayout,1,6,1,2);
        ui->gridFieldInput->addWidget(ui->labelMasterRole,2,0);ui->gridFieldInput->addWidget(ui->comboMasterRole,2,1);ui->gridFieldInput->addWidget(ui->labelTerminalRole,2,2);ui->gridFieldInput->addWidget(ui->comboTerminalRole,2,3);
        if(fieldAdvancedToggle)ui->gridFieldInput->addWidget(fieldAdvancedToggle,2,4,1,2);
        if(fieldAdvanced)ui->gridFieldInput->addWidget(fieldAdvanced,3,0,1,6);
        ui->gridFieldInput->addWidget(ui->labelTerminalModeHint,2,6);ui->gridFieldInput->addWidget(ui->labelWorkflowState,3,6,1,2);
    }
    if(fieldAdvanced)fieldAdvanced->show();
    if(fieldAdvancedToggle)fieldAdvancedToggle->hide();

    ui->tableLayerStatus->setMinimumWidth(compact?360:430);
    ui->diagnosisSplitter->setOrientation(narrow?Qt::Vertical:Qt::Horizontal);
    if(narrow)ui->diagnosisSplitter->setSizes({260,260});
    else if(compact)ui->diagnosisSplitter->setSizes({540,660});
    else ui->diagnosisSplitter->setSizes({520,760});
    if(auto* detailToggle=ui->diagnosisDetailTabs->findChild<QPushButton*>(QStringLiteral("btnToggleLayerDetail"))){
        if(!detailToggle->property("userToggled").toBool())ui->txtLayerDetail->setVisible(!compact);
        detailToggle->setText(ui->txtLayerDetail->isVisible()?QStringLiteral("收起层详情 ▲"):QStringLiteral("展开层详情 ▼"));
    }

    // Capture parameters/actions are kept in predictable rows.
    clearLayoutItems(ui->gridCaptureControl);
    if(narrow){
        ui->gridCaptureControl->addWidget(ui->labelCaptureMode,0,0);ui->gridCaptureControl->addWidget(ui->comboCaptureMode,0,1);
        ui->gridCaptureControl->addWidget(ui->labelIface,1,0);ui->gridCaptureControl->addWidget(m_captureIfacePanel,1,1,1,3);
        ui->gridCaptureControl->addWidget(ui->labelCaptureTarget,2,0);ui->gridCaptureControl->addWidget(ui->editCaptureTarget,2,1,1,2);ui->gridCaptureControl->addWidget(ui->labelCaptureBusinessPort,2,3);ui->gridCaptureControl->addWidget(ui->spinCapturePort,2,4);
    }else if(compact){
        ui->gridCaptureControl->addWidget(ui->labelCaptureMode,0,0);ui->gridCaptureControl->addWidget(ui->comboCaptureMode,0,1);ui->gridCaptureControl->addWidget(ui->labelIface,0,2);ui->gridCaptureControl->addWidget(m_captureIfacePanel,0,3,1,3);
        ui->gridCaptureControl->addWidget(ui->labelCaptureTarget,1,0);ui->gridCaptureControl->addWidget(ui->editCaptureTarget,1,1,1,3);ui->gridCaptureControl->addWidget(ui->labelCaptureBusinessPort,1,4);ui->gridCaptureControl->addWidget(ui->spinCapturePort,1,5);
    }else{
        ui->gridCaptureControl->addWidget(ui->labelCaptureMode,0,0);ui->gridCaptureControl->addWidget(ui->comboCaptureMode,0,1);ui->gridCaptureControl->addWidget(ui->labelIface,0,2);ui->gridCaptureControl->addWidget(m_captureIfacePanel,0,3);ui->gridCaptureControl->addWidget(ui->labelCaptureTarget,0,4);ui->gridCaptureControl->addWidget(ui->editCaptureTarget,0,5);ui->gridCaptureControl->addWidget(ui->labelCaptureBusinessPort,0,6);ui->gridCaptureControl->addWidget(ui->spinCapturePort,0,7);
    }

    clearLayoutItems(ui->captureActionLayout);
    for(int i=0;i<8;++i)ui->captureActionLayout->setColumnStretch(i,0);
    if(narrow){
        ui->captureActionLayout->addWidget(ui->labelCaptureState,0,0,1,4);ui->captureActionLayout->addWidget(ui->labelCapturePlan,1,0,1,4);
        ui->captureActionLayout->addWidget(ui->btnToggleCaptureAdvanced,2,0);ui->captureActionLayout->addWidget(ui->btnStartCapture,2,1);ui->captureActionLayout->addWidget(ui->btnStopCapture,2,2);ui->captureActionLayout->addWidget(ui->btnExportPcap,2,3);
    }else if(compact){
        ui->captureActionLayout->addWidget(ui->labelCaptureState,0,0,1,3);ui->captureActionLayout->addWidget(ui->labelCapturePlan,1,0,1,3);
        ui->captureActionLayout->addWidget(ui->btnToggleCaptureAdvanced,0,3);ui->captureActionLayout->addWidget(ui->btnStartCapture,0,4);ui->captureActionLayout->addWidget(ui->btnStopCapture,0,5);ui->captureActionLayout->addWidget(ui->btnExportPcap,0,6);
    }else{
        ui->captureActionLayout->addWidget(ui->labelCapturePlan,0,0);ui->captureActionLayout->addWidget(ui->labelCaptureState,0,1);ui->captureActionLayout->addWidget(ui->btnToggleCaptureAdvanced,0,3);ui->captureActionLayout->addWidget(ui->btnStartCapture,0,4);ui->captureActionLayout->addWidget(ui->btnStopCapture,0,5);ui->captureActionLayout->addWidget(ui->btnExportPcap,0,6);ui->captureActionLayout->setColumnStretch(2,1);
    }

    if(auto* packetStatsSplitter=ui->packetTopPane->findChild<QSplitter*>(QStringLiteral("packetStatsSplitter"))){
        packetStatsSplitter->setOrientation(narrow?Qt::Vertical:Qt::Horizontal);
    }
    ui->txtStats->setMaximumWidth(QWIDGETSIZE_MAX);
    ui->txtStats->setMaximumHeight(QWIDGETSIZE_MAX);

    ui->verticalLayout->setContentsMargins(narrow?6:(compact?8:14),narrow?5:(compact?6:10),narrow?6:(compact?8:14),narrow?5:(compact?6:10));
    ui->verticalLayout->setSpacing(narrow?5:(compact?6:10));
}

void MainWindow::applyProfessionalStyle(){
    ui->btnConnect->setProperty("role","primary");
    ui->btnOneClickDiagnosis->setProperty("role","primary");
    ui->btnStartCapture->setProperty("role","primary");
    ui->btnReplayPcap->setProperty("role","primary");
    ui->btnCancelOneClick->setProperty("role","danger");
    ui->btnStopCapture->setProperty("role","danger");
    ui->btnStopReplay->setProperty("role","danger");
    ui->btnToggleDeviceDetails->setProperty("role","quiet");
    ui->btnToggleCaptureAdvanced->setProperty("role","quiet");
    ui->btnToggleRuntimeLog->setProperty("role","quiet");

    // FieldLite: reduce visual noise. Use whitespace, typography and state color
    // instead of nested boxes/frames. Keep the existing object names and workflow.
    setStyleSheet(QStringLiteral(R"QSS(
QMainWindow, QWidget#centralwidget {
    background: #f6f8fa;
    color: #263746;
    font-family: "Microsoft YaHei UI";
    font-size: 10pt;
}
QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; border: none; }
QFrame { border: none; background: transparent; }
QGroupBox {
    background: transparent;
    border: none;
    margin-top: 10px;
    padding-top: 8px;
    font-weight: 700;
    color: #31485b;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 2px;
    padding: 0;
}
QWidget#fieldSummaryPanel {
    background: #ffffff;
    border: none;
    border-radius: 10px;
    padding: 4px;
}
QWidget#fieldSummaryPanel[state="normal"] { border-left: 4px solid #2b8a62; }
QWidget#fieldSummaryPanel[state="warning"] { border-left: 4px solid #d3992f; }
QWidget#fieldSummaryPanel[state="error"] { border-left: 4px solid #c44940; }
QWidget#fieldSummaryPanel[state="running"] { border-left: 4px solid #2f77ad; }
QLabel[fieldSummaryTitle], QLabel#fieldSummaryTitle { color: #718296; font-size: 9pt; font-weight: 600; }
QLabel#fieldSummaryStatus { font-size: 14pt; font-weight: 800; color: #516274; }
QLabel#fieldSummaryStatus[state="normal"] { color: #176b46; }
QLabel#fieldSummaryStatus[state="warning"] { color: #8a5a00; }
QLabel#fieldSummaryStatus[state="error"] { color: #a52a22; }
QLabel#fieldSummaryStatus[state="running"] { color: #24679b; }
QLabel#fieldSummaryStage, QLabel#fieldSummaryNext { color: #29445d; font-weight: 600; }
QLineEdit, QSpinBox, QComboBox {
    min-height: 30px;
    background: #ffffff;
    border: 1px solid #d5dee6;
    border-radius: 5px;
    padding: 0 8px;
    selection-background-color: #dcecf8;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid #6f9fbe; }
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled { background: #f0f3f5; color: #8997a5; }
QComboBox QAbstractItemView {
    background: #ffffff;
    color: #29445d;
    border: 1px solid #9bb8cc;
    border-radius: 5px;
    outline: 0;
    selection-background-color: #dcecf8;
    selection-color: #17324a;
}
QComboBox QAbstractItemView::item { min-height: 28px; padding: 3px 8px; background: #ffffff; }
QComboBox QAbstractItemView::item:hover { background: #edf5fa; }
QComboBox QAbstractItemView::item:selected { background: #dcecf8; color: #17324a; }
QPushButton {
    min-height: 30px;
    padding: 0 13px;
    background: #ffffff;
    color: #29445d;
    border: 1px solid #d5dee6;
    border-radius: 5px;
    font-weight: 600;
}
QPushButton:hover { background: #f0f6fa; border-color: #9bb8cc; }
QPushButton:pressed { background: #e4eef5; }
QPushButton:disabled { background: #eef2f4; color: #9aa6b2; border-color: #e0e5e9; }
QPushButton[role="primary"] { background: #2f77ad; color: #ffffff; border: none; min-height: 38px; padding-left: 18px; padding-right: 18px; }
QPushButton[role="primary"]:hover { background: #28678f; }
QPushButton[role="danger"] { background: #fff7f6; color: #a73229; border-color: #e3b0ab; }
QPushButton[role="quiet"] { background: transparent; color: #46738f; border: none; font-weight: 500; }
QTabWidget::pane { border: none; background: transparent; }
QTabBar::tab {
    min-width: 88px;
    min-height: 34px;
    padding: 0 12px;
    margin-right: 5px;
    background: transparent;
    color: #718294;
    border: none;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:hover { color: #24679b; background: #edf4f8; border-radius: 5px; }
QTabBar::tab:selected { color: #185d91; font-weight: 700; border-bottom: 3px solid #2f77ad; }
QTableWidget {
    background: #ffffff;
    alternate-background-color: #fafbfc;
    border: none;
    border-radius: 5px;
    gridline-color: #edf0f2;
    selection-background-color: #e3f0f8;
    selection-color: #173c59;
}
QHeaderView::section {
    background: #f3f6f8;
    color: #52687a;
    border: none;
    border-bottom: 1px solid #e1e7eb;
    padding: 7px;
    font-weight: 700;
}
QPlainTextEdit {
    background: #fbfcfd;
    color: #26384a;
    border: none;
    border-radius: 5px;
    padding: 7px;
}
QLabel#labelOverallConclusion {
    background: #ffffff;
    border: none;
    border-left: 4px solid #2f77ad;
    border-radius: 5px;
    padding: 10px 13px;
    color: #24445f;
    font-weight: 600;
}
QLabel#labelWorkflowState, QLabel#labelConnectionState, QLabel#labelWanSummary, QLabel#labelPingResultSummary { color: #1c5f8f; font-weight: 700; }
QLabel[hint="true"] { color: #687b8d; font-size: 9pt; }
QLabel[statusCard="true"] {
    min-width: 136px;
    padding: 10px 12px;
    border: none;
    border-radius: 8px;
    background: #ffffff;
    color: #536779;
    font-weight: 600;
}
QLabel[statusCard="true"][state="normal"] { background: #edf8f2; color: #176b46; }
QLabel[statusCard="true"][state="warning"] { background: #fff8e8; color: #8a5a00; }
QLabel[statusCard="true"][state="error"] { background: #fff0ef; color: #a52a22; }
QLabel[statusCard="true"][state="untested"], QLabel[statusCard="true"][state="unknown"] { background: #f1f4f6; color: #637486; }
QSplitter::handle { background: #e8edf1; }
QSplitter::handle:hover { background: #cbd9e3; }
QStatusBar { background: #eef2f4; color: #536779; border-top: 1px solid #e2e7ea; }
QToolTip { background: #263746; color: #ffffff; border: none; padding: 5px 7px; }
)QSS"));

    const QFont fixed=QFontDatabase::systemFont(QFontDatabase::FixedFont);
    ui->txtDiagnosis->setFont(fixed);
    ui->txtLayerDetail->setFont(fixed);
    ui->txtTcpSessions->setFont(fixed);
    ui->txtFieldDiagnosis->setFont(fixed);
    ui->txtPacketDetail->setFont(fixed);
    ui->txtPacketHex->setFont(fixed);
    ui->txtRealtimeTcpSessions->setFont(fixed);
    ui->txtPacketBusiness->setFont(fixed);
    ui->txtStats->setFont(fixed);
    ui->txtPingResult->setFont(fixed);
    ui->txtStats->setPlainText(QStringLiteral("总包数：0\n总字节：0\n\nTCP：0\nUDP：0\nICMP：0\n\nTCP会话：0"));
}

void MainWindow::log(const QString& s){
    ui->txtDiagnosis->appendPlainText(QStringLiteral("[%1] %2").arg(QTime::currentTime().toString("HH:mm:ss"),s));
}

void MainWindow::beginPingDisplay(const QString& target){
    if(!ui->groupPingResult)return;
    if(m_pingPanelManager)m_pingPanelManager->setPanelVisible(true);
    else ui->groupPingResult->show();
    ui->labelPingResultSummary->setText(QStringLiteral("正在 Ping %1 ...").arg(target));
    ui->txtPingResult->clear();
    ui->txtPingResult->appendPlainText(QStringLiteral("目标：%1\n").arg(target));
}

void MainWindow::appendPingDisplay(const QString& chunk){
    if(!ui->txtPingResult || chunk.isEmpty())return;
    ui->txtPingResult->moveCursor(QTextCursor::End);
    ui->txtPingResult->insertPlainText(chunk);
    ui->txtPingResult->verticalScrollBar()->setValue(ui->txtPingResult->verticalScrollBar()->maximum());
}

void MainWindow::finishPingDisplay(const QString& target,const PingResult& result){
    if(!ui->labelPingResultSummary)return;
    QStringList parts;
    QString status;
    if(result.reachable)status=QStringLiteral("可达");
    else if(result.failureKind==PingFailureKind::NoEchoReply || (result.validOutput&&result.received==0&&result.failureKind==PingFailureKind::None))
        status=QStringLiteral("未收到ICMP应答");
    else if(result.failureKind==PingFailureKind::NetworkUnreachable || result.failureKind==PingFailureKind::DestinationHostUnreachable)
        status=QStringLiteral("不可达");
    else
        status=QStringLiteral("未收到ICMP应答/状态未知");
    parts<<QStringLiteral("%1：%2").arg(target,status);
    if(result.transmitted>=0&&result.received>=0)parts<<QStringLiteral("发送 %1 / 接收 %2").arg(result.transmitted).arg(result.received);
    if(result.packetLossPercent>=0)parts<<QStringLiteral("丢包 %1%").arg(result.packetLossPercent);
    if(result.avgRttMs>=0)parts<<QStringLiteral("RTT %1/%2/%3 ms").arg(result.minRttMs,0,'f',1).arg(result.avgRttMs,0,'f',1).arg(result.maxRttMs,0,'f',1);
    if(!result.failureReason.isEmpty())parts<<result.failureReason;
    ui->labelPingResultSummary->setText(parts.join(QStringLiteral(" | ")));
    if(ui->txtPingResult->toPlainText().trimmed().isEmpty()&&!result.rawOutput.isEmpty())ui->txtPingResult->setPlainText(result.rawOutput);
}

void MainWindow::updateCaptureActivityState(const QString& detail,LayerState state){
    const QString iface=m_activeCaptureIface.isEmpty()?QStringLiteral("--"):m_activeCaptureIface;
    const QString filter=m_activeCaptureFilter.isEmpty()?QStringLiteral("全部流量"):m_activeCaptureFilter;
    const QString text=QStringLiteral("运行中 | 接口 %1 | 已捕获 %2 包 / %3 B | %4\n过滤：%5")
        .arg(iface).arg(m_lastCaptureStats.totalPackets).arg(m_lastCaptureStats.totalBytes).arg(detail,filter);
    setCaptureState(text,state);
}

void MainWindow::setCaptureState(const QString& text,LayerState state){
    if(!ui->labelCaptureState)return;
    ui->labelCaptureState->setText(QStringLiteral("状态：%1").arg(text));
    QString color=QStringLiteral("#52606d");
    QString background=QStringLiteral("#eef2f6");
    if(state==LayerState::Normal){color=QStringLiteral("#176b46");background=QStringLiteral("#e8f5ee");}
    else if(state==LayerState::Warning){color=QStringLiteral("#8a5a00");background=QStringLiteral("#fff3d1");}
    else if(state==LayerState::Error){color=QStringLiteral("#a52a22");background=QStringLiteral("#fdebea");}
    ui->labelCaptureState->setStyleSheet(QStringLiteral("QLabel{color:%1;background:%2;border:1px solid #d4dde5;border-radius:6px;padding:4px 8px;font-weight:600;}").arg(color,background));
}

void MainWindow::startBackgroundModuleLog(){
    if(routerSerialMode())return; // physical serial console is a single shared shell
    if(!m_moduleLog || !m_controlLoggedIn || m_routerDisconnectRequested)return;
    if(m_moduleLog->isConnected())return;
    m_liveModuleLogBuffer.clear();
    m_moduleLogSetupState=ModuleLogSetupState::Idle;
    log(QStringLiteral("正在建立独立模组日志 Telnet，会自动检查 debuglog_enable/syslogd_enable"));
    m_moduleLog->connectToHost(ui->editHost->text().trimmed(),quint16(ui->spinPort->value()));
}

void MainWindow::mergeLiveWanStatus(const WanStatus& live){
    auto assign=[&](QString& dst,const QString& src){if(!src.trimmed().isEmpty())dst=src;};
    assign(m_lastStatus.wanIfname,live.wanIfname);
    assign(m_lastStatus.wanTopology,live.wanTopology);
    if(live.primaryWanPresent)m_lastStatus.primaryWanPresent=true;
    if(live.backupWanPresent)m_lastStatus.backupWanPresent=true;
    if(ConnectivityProbe::isUsableWanIpv4(live.wanIp)){
        m_lastStatus.wanIp=live.wanIp;
        if(!live.wanIpFromNvramSnapshot){
            m_lastStatus.wanIpFromNvramSnapshot=false;
            m_lastStatus.wanIpSource=live.wanIpSource.isEmpty()?QStringLiteral("实时日志"):live.wanIpSource;
        }
    }
    if(ConnectivityProbe::isUsableWanIpv4(live.backupWanIp))m_lastStatus.backupWanIp=live.backupWanIp;
    if(plausibleModuleCardValue(live.moduleName))assign(m_lastStatus.moduleName,live.moduleName);
    assign(m_lastStatus.moduleCode,live.moduleCode);
    assign(m_lastStatus.firmware,live.firmware);
    assign(m_lastStatus.moduleControlDevice,live.moduleControlDevice);
    if(!live.simStatus.trimmed().isEmpty()){
        m_lastStatus.simStatus=live.simStatus;
        if(!live.simStatusFromNvram)m_lastStatus.simStatusFromNvram=false;
    }
    assign(m_lastStatus.cpinRaw,live.cpinRaw);
    assign(m_lastStatus.simCardRaw,live.simCardRaw);
    assign(m_lastStatus.cereg,live.cereg);assign(m_lastStatus.cgreg,live.cgreg);assign(m_lastStatus.c5greg,live.c5greg);assign(m_lastStatus.creg,live.creg);
    assign(m_lastStatus.mcc,live.mcc);assign(m_lastStatus.mnc,live.mnc);assign(m_lastStatus.lac,live.lac);assign(m_lastStatus.cellId,live.cellId);assign(m_lastStatus.band,live.band);
    assign(m_lastStatus.apn,live.apn);assign(m_lastStatus.dcuIp,live.dcuIp);assign(m_lastStatus.observedTerminalTransport,live.observedTerminalTransport);
    assign(m_lastStatus.operatorName,live.operatorName);if(live.operatorMode>=0)m_lastStatus.operatorMode=live.operatorMode;if(live.operatorFormat>=0)m_lastStatus.operatorFormat=live.operatorFormat;if(live.operatorAccessTechnology>=0)m_lastStatus.operatorAccessTechnology=live.operatorAccessTechnology;
    m_lastStatus.moduleAtResponsive=m_lastStatus.moduleAtResponsive||live.moduleAtResponsive;
    m_lastStatus.moduleDetected=m_lastStatus.moduleDetected||live.moduleDetected;
    m_lastStatus.pppConnected=m_lastStatus.pppConnected||live.pppConnected;
    m_lastStatus.cellularDialSeen=m_lastStatus.cellularDialSeen||live.cellularDialSeen;
    m_lastStatus.dtsStarted=m_lastStatus.dtsStarted||live.dtsStarted;
    m_lastStatus.southTcpConfigured=m_lastStatus.southTcpConfigured||live.southTcpConfigured;
    m_lastStatus.southTcpConnected=m_lastStatus.southTcpConnected||live.southTcpConnected;
    if(live.csq>=0)m_lastStatus.csq=live.csq;
    if(live.rssi!=999)m_lastStatus.rssi=live.rssi;
    if(live.rsrp!=999)m_lastStatus.rsrp=live.rsrp;
    if(live.rsrq!=999)m_lastStatus.rsrq=live.rsrq;
    if(live.sinr!=999)m_lastStatus.sinr=live.sinr;
    if(live.cgatt>=0)m_lastStatus.cgatt=live.cgatt;
    if(live.pci>=0)m_lastStatus.pci=live.pci;
    if(live.earfcn>=0)m_lastStatus.earfcn=live.earfcn;
    if(live.dialFinish>=0)m_lastStatus.dialFinish=live.dialFinish;
    if(live.dcuPort>=0)m_lastStatus.dcuPort=live.dcuPort;
    if(live.serialBaudrate>=0)m_lastStatus.serialBaudrate=live.serialBaudrate;
    if(live.serialDatabit>=0)m_lastStatus.serialDatabit=live.serialDatabit;
    if(live.serialStopbit>=0)m_lastStatus.serialStopbit=live.serialStopbit;
    if(live.serialParity>=0)m_lastStatus.serialParity=live.serialParity;
    if(live.serialFlowcontrol>=0)m_lastStatus.serialFlowcontrol=live.serialFlowcontrol;
    m_lastStatus.cpinErrorCount=qMax(m_lastStatus.cpinErrorCount,live.cpinErrorCount);
    m_lastStatus.networkUnreachableCount=qMax(m_lastStatus.networkUnreachableCount,live.networkUnreachableCount);
    m_lastStatus.wanNotUpCount=qMax(m_lastStatus.wanNotUpCount,live.wanNotUpCount);
    m_lastStatus.lcpRequestCount=qMax(m_lastStatus.lcpRequestCount,live.lcpRequestCount);
    m_lastStatus.lcpAckCount=qMax(m_lastStatus.lcpAckCount,live.lcpAckCount);
    m_lastStatus.ipcpRequestCount=qMax(m_lastStatus.ipcpRequestCount,live.ipcpRequestCount);
    m_lastStatus.ipcpAckCount=qMax(m_lastStatus.ipcpAckCount,live.ipcpAckCount);
    m_lastStatus.ipcpNakCount=qMax(m_lastStatus.ipcpNakCount,live.ipcpNakCount);
    // Current failure flags reflect the recent live window; historical counters remain monotonic.
    m_lastStatus.physicalLinkDown=live.physicalLinkDown;
    m_lastStatus.dhcpFailure=live.dhcpFailure;
    m_lastStatus.pppoeFailure=live.pppoeFailure;
    m_lastStatus.wanNetworkFailed=live.wanNetworkFailed;
    m_lastStatus.physicalLinkDownCount=qMax(m_lastStatus.physicalLinkDownCount,live.physicalLinkDownCount);
    m_lastStatus.dhcpFailureCount=qMax(m_lastStatus.dhcpFailureCount,live.dhcpFailureCount);
    m_lastStatus.pppoeFailureCount=qMax(m_lastStatus.pppoeFailureCount,live.pppoeFailureCount);
    m_lastStatus.wanNetworkFailedCount=qMax(m_lastStatus.wanNetworkFailedCount,live.wanNetworkFailedCount);
    if(!live.tailLines.isEmpty())m_lastStatus.tailLines=live.tailLines;
}

void MainWindow::processBackgroundModuleLogText(const QString& text){
    if(text.isEmpty())return;
    m_liveModuleLogBuffer+=text;
    constexpr int MaxLiveLogChars=512*1024;
    if(m_liveModuleLogBuffer.size()>MaxLiveLogChars)m_liveModuleLogBuffer.remove(0,m_liveModuleLogBuffer.size()-MaxLiveLogChars);
    // Parse a bounded recent window for current-state flags so an old link-down/DHCP error
    // does not stay active forever. Historical counters are kept separately by mergeLiveWanStatus().
    constexpr int CurrentStateWindowChars=32*1024;
    const QString recent=m_liveModuleLogBuffer.right(CurrentStateWindowChars);
    const WanStatus live=LogAnalyzer::analyze(recent);
    const WanStatus history=LogAnalyzer::analyze(m_liveModuleLogBuffer);
    mergeLiveWanStatus(live);
    m_lastStatus.physicalLinkDownCount=qMax(m_lastStatus.physicalLinkDownCount,history.physicalLinkDownCount);
    m_lastStatus.dhcpFailureCount=qMax(m_lastStatus.dhcpFailureCount,history.dhcpFailureCount);
    m_lastStatus.pppoeFailureCount=qMax(m_lastStatus.pppoeFailureCount,history.pppoeFailureCount);
    m_lastStatus.wanNetworkFailedCount=qMax(m_lastStatus.wanNetworkFailedCount,history.wanNetworkFailedCount);
    m_lastStatus.networkUnreachableCount=qMax(m_lastStatus.networkUnreachableCount,history.networkUnreachableCount);
    m_lastStatus.wanNotUpCount=qMax(m_lastStatus.wanNotUpCount,history.wanNotUpCount);
    const bool hasLiveEvidence=live.moduleAtResponsive||live.moduleDetected||!live.moduleName.isEmpty()||!live.simStatus.isEmpty()||
        !live.cereg.isEmpty()||!live.cgreg.isEmpty()||!live.c5greg.isEmpty()||live.rsrp!=999||live.sinr!=999||
        (!live.wanIfname.isEmpty())||(ConnectivityProbe::isUsableWanIpv4(live.wanIp));
    if(hasLiveEvidence && m_lastDiagnosis.type.isEmpty())m_lastDiagnosis.type=QStringLiteral("LIVE_MODULE_LOG");
    renderFieldDiagnosis();
}

void MainWindow::clearPacketView(){
    if(m_protocolRefreshTimer)m_protocolRefreshTimer->stop();
    m_tcpReassembler.reset();
    m_packetNo=0;
    m_packetChannelAnalyzer.reset();
    ui->tablePackets->setRowCount(0);
    ui->txtStats->clear();
    ui->txtPacketDetail->clear();
    ui->txtPacketHex->clear();
    ui->txtRealtimeTcpSessions->clear();
    ui->txtPacketBusiness->clear();
    if(ui->checkFollowLatestPacket)ui->checkFollowLatestPacket->setChecked(true);
}

void MainWindow::applyDiagnosis(const WanStatus& s,const DiagnosisResult& d,const QString& report){
    m_lastStatus=s;
    m_lastDiagnosis=d;
    m_lastReport=report;
    if(!s.wanIfname.isEmpty())ui->labelWanSummary->setText(QStringLiteral("WAN：%1  %2").arg(s.wanIfname,s.wanIp));
    log(QStringLiteral("WAN诊断完成: ")+d.conclusion);
    statusBar()->showMessage(d.conclusion,5000);
}

bool MainWindow::routerSerialMode() const
{
    return ui && ui->comboRouterConnectionMode && ui->comboRouterConnectionMode->currentIndex()==1;
}

bool MainWindow::captureTransportReady() const
{
    if(routerSerialMode())return m_controlLoggedIn && m_control && m_control->isConnected();
    return m_captureLoggedIn && m_capture && m_capture->isConnected();
}

void MainWindow::refreshSerialPorts()
{
    if(!ui || !ui->comboPcSerialPort)return;
    const QString previous=ui->comboPcSerialPort->currentData().toString();
    const QList<QSerialPortInfo> ports=QSerialPortInfo::availablePorts();
    ui->comboPcSerialPort->clear();
    for(const QSerialPortInfo& info:ports){
        QString label=info.portName();
        const QString description=info.description().trimmed();
        if(!description.isEmpty() && !label.contains(description,Qt::CaseInsensitive))
            label+=QStringLiteral(" — %1").arg(description);
        ui->comboPcSerialPort->addItem(label,info.portName());
    }
    if(ui->comboPcSerialPort->count()==0){
        ui->comboPcSerialPort->addItem(QStringLiteral("未检测到可用串口"),QString());
        ui->comboPcSerialPort->setEnabled(false);
        updateConnectionUi();
        return;
    }
    ui->comboPcSerialPort->setEnabled(true);
    const int previousIndex=ui->comboPcSerialPort->findData(previous);
    ui->comboPcSerialPort->setCurrentIndex(previousIndex>=0?previousIndex:0);
    updateConnectionUi();
}

void MainWindow::updateRouterConnectionModeUi()
{
    const bool serial=routerSerialMode();
    ui->labelHost->setVisible(!serial);
    ui->editHost->setVisible(!serial);
    ui->labelPort->setVisible(!serial);
    ui->spinPort->setVisible(!serial);
    ui->labelHistory->setVisible(!serial);
    ui->comboConnectionHistory->setVisible(!serial);
    ui->serialSettingsPanel->setVisible(serial);
    if(serial && !m_control->isConnected())refreshSerialPorts();
    if(!m_control->isConnected() && !m_capture->isConnected())
        ui->labelConnectionState->setText(serial?QStringLiteral("未连接（串口控制台）"):QStringLiteral("未连接"));
    updateConnectionUi();
}

void MainWindow::loginClient(TelnetClient* c,const QString&){
    c->connectToHost(ui->editHost->text().trimmed(),quint16(ui->spinPort->value()));
}

void MainWindow::abortRouterConnectionAttempt(const QString& reason)
{
    if(!m_routerConnectInProgress && m_routerDisconnectRequested && !m_routerConnectionFailureMessage.isEmpty())return;

    m_routerConnectInProgress=false;
    m_routerDisconnectRequested=true;
    m_waitingCaptureReconnectForWorkflow=false;
    m_routerConnectionFailureMessage=QStringLiteral("登录/连接失败，已自动断开：%1").arg(reason);

    if(m_workflow&&m_workflow->isRunning())m_workflow->cancel();
    if(m_workflowCaptureTimer)m_workflowCaptureTimer->stop();
    if(m_captureNoTrafficTimer)m_captureNoTrafficTimer->stop();
    if(m_capCtrl&&m_capCtrl->isRunning())m_capCtrl->stop();
    for(CaptureSessionWidget* session:m_captureSessions)if(session&&session->isRunning())session->stopCapture();
    m_syncWorkflowCaptureActive=false;
    m_syncCaptureSharedInterface=false;
    m_dualCaptureCorrelator.reset();
    if(m_diag&&m_diag->isRunning())m_diag->cancel();

    if(m_control&&m_control->isConnected())m_control->disconnectFromHost();
    if(m_capture&&m_capture->isConnected())m_capture->disconnectFromHost();
    if(m_moduleLog&&m_moduleLog->isConnected())m_moduleLog->disconnectFromHost();
    m_moduleLogSetupState=ModuleLogSetupState::Idle;
    m_controlLoggedIn=false;
    m_captureLoggedIn=false;
    if(m_capCtrl)m_capCtrl->setSingleSession(false);

    ui->labelConnectionState->setText(m_routerConnectionFailureMessage);
    log(m_routerConnectionFailureMessage);
    updateConnectionUi();
}

void MainWindow::connectRouter(){
    if(m_control->isConnected()||m_capture->isConnected()){log(QStringLiteral("已有连接，请先断开后重新连接"));return;}
    m_routerDisconnectRequested=false;
    m_routerConnectInProgress=false;
    m_routerConnectionFailureMessage.clear();
    m_discoveredWanIfname.clear();m_discoveredWanIp.clear();m_discoveredWanIpSource.clear();m_discoveredInterfaces.clear();
    m_lastStatus.wanIfname.clear();m_lastStatus.wanIp=QStringLiteral("0.0.0.0");m_lastStatus.backupWanIp=QStringLiteral("0.0.0.0");
    m_lastStatus.moduleName.clear();m_lastStatus.firmware.clear();m_lastStatus.moduleControlDevice.clear();
    m_lastStatus.moduleAtResponsive=false;m_lastStatus.moduleDetected=false;
    m_lastStatus.moduleProbeAttempted=false;m_lastStatus.moduleProbeCompleted=false;
    m_lastStatus.defaultRouteChecked=false;m_lastStatus.defaultRoutePresent=false;
    m_lastStatus.defaultGateway.clear();m_lastStatus.defaultRouteInterface.clear();
    m_lastStatus.wanInterfaceStateKnown=false;m_lastStatus.wanInterfaceUp=false;
    m_lastStatus.simStatus.clear();m_lastStatus.cpinRaw.clear();m_lastStatus.simCardRaw.clear();m_lastStatus.cpinErrorCount=0;
    m_lastStatus.cereg.clear();m_lastStatus.cgreg.clear();m_lastStatus.creg.clear();m_lastStatus.c5greg.clear();
    m_lastDiagnosis=DiagnosisResult{};
    setStatusCard(ui->labelCardModule,QStringLiteral("模组"),QStringLiteral("未测试"),LayerState::NotTested);
    setStatusCard(ui->labelCardSim,QStringLiteral("SIM"),QStringLiteral("未测试"),LayerState::NotTested);
    setStatusCard(ui->labelCardRegistration,QStringLiteral("网络注册"),QStringLiteral("未测试"),LayerState::NotTested);
    setStatusCard(ui->labelCardWan,QStringLiteral("WAN"),QStringLiteral("未测试"),LayerState::NotTested);
    setStatusCard(ui->labelCardWanIp,QStringLiteral("WAN IP"),QStringLiteral("未测试"),LayerState::NotTested);
    setStatusCard(ui->labelCardSignal,QStringLiteral("无线信号"),QStringLiteral("未测试"),LayerState::NotTested);
    m_controlLoggedIn=false;m_captureLoggedIn=false;

    if(routerSerialMode()){
        refreshSerialPorts();
        const QString serialPort=ui->comboPcSerialPort->currentData().toString().trimmed();
        if(serialPort.isEmpty()){
            ui->labelConnectionState->setText(QStringLiteral("未检测到可用PC串口"));
            log(QStringLiteral("串口连接失败：PC 未检测到可用串口，请插入串口设备后刷新"));
            updateConnectionUi();
            return;
        }
        const qint32 baud=ui->comboSerialBaud->currentText().toInt();
        const QSerialPort::DataBits dataBits=ui->comboSerialDataBits->currentText()==QStringLiteral("7")?QSerialPort::Data7:QSerialPort::Data8;
        const QSerialPort::StopBits stopBits=ui->comboSerialStopBits->currentText()==QStringLiteral("2")?QSerialPort::TwoStop:QSerialPort::OneStop;
        QSerialPort::Parity parity=QSerialPort::NoParity;
        if(ui->comboSerialParity->currentText()==QStringLiteral("E"))parity=QSerialPort::EvenParity;
        else if(ui->comboSerialParity->currentText()==QStringLiteral("O"))parity=QSerialPort::OddParity;
        m_capCtrl->setSingleSession(true);
        m_routerConnectInProgress=true;
        ui->labelConnectionState->setText(QStringLiteral("正在打开串口 %1（%2 %3%4%5）...")
            .arg(serialPort).arg(baud).arg(ui->comboSerialDataBits->currentText()).arg(ui->comboSerialStopBits->currentText()).arg(ui->comboSerialParity->currentText()));
        m_control->connectToSerial(serialPort,baud,dataBits,parity,stopBits,QSerialPort::NoFlowControl);
        updateConnectionUi();
        return;
    }

    m_capCtrl->setSingleSession(false);
    m_routerConnectInProgress=true;
    ui->labelConnectionState->setText(QStringLiteral("正在连接 %1:%2...").arg(ui->editHost->text().trimmed()).arg(ui->spinPort->value()));
    loginClient(m_control,"控制连接");
    if(m_routerDisconnectRequested){updateConnectionUi();return;}
    loginClient(m_capture,"抓包连接");
    updateConnectionUi();
}

void MainWindow::disconnectRouter(){
    m_routerDisconnectRequested=true;
    m_routerConnectInProgress=false;
    m_routerConnectionFailureMessage.clear();
    m_waitingCaptureReconnectForWorkflow=false;
    if(m_workflow&&m_workflow->isRunning())m_workflow->cancel();
    if(m_workflowCaptureTimer)m_workflowCaptureTimer->stop();
    if(m_capCtrl&&m_capCtrl->isRunning())m_capCtrl->stop();
    for(CaptureSessionWidget* session:m_captureSessions)if(session&&session->isRunning())session->stopCapture();
    m_syncWorkflowCaptureActive=false;
    m_syncCaptureSharedInterface=false;
    m_dualCaptureCorrelator.reset();
    if(m_diag&&m_diag->isRunning())m_diag->cancel();
    if(m_control)m_control->disconnectFromHost();
    if(m_capture)m_capture->disconnectFromHost();
    if(m_moduleLog)m_moduleLog->disconnectFromHost();
    m_moduleLogSetupState=ModuleLogSetupState::Idle;
    m_controlLoggedIn=false;m_captureLoggedIn=false;
    if(m_capCtrl)m_capCtrl->setSingleSession(false);
    ui->labelConnectionState->setText(QStringLiteral("已断开"));
    updateConnectionUi();
}

void MainWindow::diagnose(){
    if(m_workflow&&m_workflow->isRunning()){log(QStringLiteral("一键现场诊断正在运行，请先停止后再单独诊断WAN"));return;}
    if(controlCommandBusy()){log(QStringLiteral("控制通道正在执行自动检测/WAN诊断/Ping，请等待当前命令完成"));return;}
    // Background evidence collection starts only after an explicit diagnostic action.
    startBackgroundModuleLog();
    m_diag->startDiagnosis();
}

void MainWindow::startCapture(){
    auto fail=[this](const QString& message){
        setCaptureState(message,LayerState::Error);
        statusBar()->showMessage(message,6000);
        log(message);
    };
    if(m_workflow&&m_workflow->isRunning()){fail(QStringLiteral("一键现场诊断正在运行，不能同时手动启动抓包"));return;}
    m_offline->stopReplay();
    if(!captureTransportReady()){fail(QStringLiteral("抓包控制通道未登录，请先连接路由器"));return;}
    if(!m_controlLoggedIn || !m_control->isConnected()){fail(QStringLiteral("控制连接未登录，无法执行抓包前检查"));return;}
    if(controlCommandBusy()){fail(QStringLiteral("控制通道正在执行自动检测/诊断命令，请稍候再开始抓包"));return;}
    if(m_capCtrl->isRunning()){fail(QStringLiteral("已有抓包正在启动或运行，请先停止当前抓包"));return;}

    const int mode=ui->comboCaptureMode->currentIndex();
    const QString target=ui->editCaptureTarget->text().trimmed();
    const QString iface=captureInterfaceText();
    static const QRegularExpression safeIface(QStringLiteral(R"(^[A-Za-z0-9_.:-]+$)"));
    if(iface.isEmpty() || !safeIface.match(iface).hasMatch()){fail(QStringLiteral("请输入有效抓包接口；可从列表选择，也可手工输入 tun0/usb0/br0/any 等"));return;}
    setCaptureState(QStringLiteral("正在准备抓包..."),LayerState::Warning);

    if(mode==0){
        // WAN抓包的自动默认仍来自可信WAN检测。若用户要抓VPN/LAN/其它接口，请用“自定义抓包”。
        if(iface!=QStringLiteral("any") && !ConnectivityProbe::isUsableWanInterfaceName(iface)){
            fail(QStringLiteral("WAN抓包当前接口不是可信WAN接口；请选择“自定义抓包”后可抓 br0/tun0/其它接口"));return;
        }
        clearPacketView();m_protocolEvidence=ProtocolEvidence{};
        if(!prepareCaptureStorage(QStringLiteral("wan"))){setCaptureState(QStringLiteral("已取消"),LayerState::Unknown);return;}
        m_fieldCaptureMode=FieldCaptureMode::None;m_fieldChannelAnalyzer.reset();m_activeCaptureIface=iface;m_activeCaptureFilter=ui->editFilter->text().trimmed();
        log(QStringLiteral("WAN抓包: tcpdump -i %1 ... %2").arg(iface,m_activeCaptureFilter));m_capCtrl->start(iface,m_activeCaptureFilter);return;
    }

    if(mode==3){
        clearPacketView();m_protocolEvidence=ProtocolEvidence{};
        if(!prepareCaptureStorage(QStringLiteral("custom"))){setCaptureState(QStringLiteral("已取消"),LayerState::Unknown);return;}
        m_fieldCaptureMode=FieldCaptureMode::None;m_fieldChannelAnalyzer.reset();m_activeCaptureIface=iface;m_activeCaptureFilter=ui->editFilter->text().trimmed();
        log(QStringLiteral("自定义抓包: tcpdump -i %1 ... %2").arg(iface,m_activeCaptureFilter.isEmpty()?QStringLiteral("全部流量"):m_activeCaptureFilter));
        m_capCtrl->start(iface,m_activeCaptureFilter);return;
    }

    if(!ConnectivityProbe::isValidIpv4(target)){fail(QStringLiteral("抓包目标 IP 无效：%1").arg(target));return;}
    if(mode==1){
        FieldDiagnosticConfig cfg=currentFieldConfig();cfg.masterIp=target;cfg.masterPort=quint16(ui->spinCapturePort->value());
        const QString filter=ui->editFilter->text().trimmed().isEmpty()?FieldDiagnosticController::buildMasterFilter(cfg):ui->editFilter->text().trimmed();
        ChannelCriteria criteria;criteria.peerIp.clear();criteria.peerPort=cfg.masterPort;criteria.requirePeerPort=true;
        startFieldCapture(FieldCaptureMode::Master,iface,filter,criteria,true);return;
    }

    FieldDiagnosticConfig cfg=currentFieldConfig();
    if(cfg.terminalTransport!=TerminalTransport::Ethernet){fail(QStringLiteral("终端当前为串口通讯；请使用WAN抓包/主站抓包/自定义抓包观察网络侧流量"));return;}
    cfg.terminalTransport=TerminalTransport::Ethernet;cfg.terminalIp=target;cfg.terminalPort=quint16(ui->spinCapturePort->value());
    QString subnetError;
    if(!validateTerminalLanSubnet(cfg.terminalIp,&subnetError)){fail(subnetError);return;}
    const QString filter=ui->editFilter->text().trimmed().isEmpty()?FieldDiagnosticController::buildTerminalFilter(cfg):ui->editFilter->text().trimmed();
    ChannelCriteria criteria;criteria.peerIp=target;criteria.peerPort=cfg.terminalPort;criteria.requirePeerPort=true;
    startFieldCapture(FieldCaptureMode::TerminalEthernet,iface,filter,criteria,true);
}

void MainWindow::stopCapture(){m_capCtrl->stop();}

void MainWindow::exportPcap(){
    const QString path=QFileDialog::getSaveFileName(this,"导出当前抓包",QStringLiteral("wan_%1.pcap").arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),"PCAP (*.pcap)");
    if(path.isEmpty())return;
    QString e;
    if(!m_capCtrl->exportBufferedPcap(path,&e))log("导出失败: "+e);
    else statusBar()->showMessage("PCAP 已保存: "+path,5000);
}

void MainWindow::saveReport(){
    QString report=currentLayeredReport();
    if(report.isEmpty())report=m_lastReport;
    if(report.isEmpty()){log("当前没有诊断报告");return;}
    const QString path=QFileDialog::getSaveFileName(this,"保存诊断报告","FourFaith_RouterDiag_diagnosis.txt","Text (*.txt)");
    if(path.isEmpty())return;
    QFile f(path);
    if(!f.open(QIODevice::WriteOnly|QIODevice::Text)){log("保存报告失败: "+f.errorString());return;}
    if(f.write(report.toUtf8())<0){log("保存报告失败: "+f.errorString());return;}
    statusBar()->showMessage("诊断报告已保存",3000);
}

void MainWindow::importSystemLog(){
    const QString path=QFileDialog::getOpenFileName(this,QStringLiteral("导入日志"),QString(),
        QStringLiteral("日志文件 (*.txt *.log);;所有文件 (*.*)"));
    if(path.isEmpty())return;
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)){log("读取日志失败: "+f.errorString());return;}
    const QByteArray bytes=f.readAll();
    QString text=QString::fromUtf8(bytes);
    if(text.contains(QChar(0xFFFD)))text=QString::fromLocal8Bit(bytes);

    const WanStatus status=LogAnalyzer::analyze(text);
    m_protocolEvidence=ProtocolDiagnosis::analyzeLogText(text);
    const DiagnosisResult diagnosis=DiagnosisEngine::diagnose(status);
    const QString report=ReportExporter::buildTextReport(status,diagnosis);
    applyDiagnosis(status,diagnosis,report);
    ui->txtDiagnosis->appendPlainText(QStringLiteral("\n[离线日志] %1").arg(QFileInfo(path).fileName()));
    ui->mainTabs->setCurrentWidget(ui->tabFieldDiagnosis);
    renderFieldDiagnosis();
}

void MainWindow::importPcap(){
    if(m_capCtrl->isRunning()){log("请先停止在线抓包，再导入离线抓包文件");return;}
    m_fieldCaptureMode=FieldCaptureMode::None;
    m_fieldChannelAnalyzer.reset();
    m_protocolEvidence=ProtocolEvidence{};
    const QString path=QFileDialog::getOpenFileName(this,QStringLiteral("导入抓包文件"),QString(),QStringLiteral("抓包文件 (*.pcap *.cap *.pcapng *.pap);;所有文件 (*.*)"));
    if(path.isEmpty())return;
    clearPacketView();
    m_offlineRecentPackets.clear();m_offlineRecentWriteIndex=0;m_offlineRecentWrapped=false;
    m_offlineBulkImport=true;
    ui->mainTabs->setCurrentWidget(ui->tabRealtimeCapture);
    ui->tablePackets->setUpdatesEnabled(false);
    QString error;
    const bool loaded=m_offline->loadFile(path,&error);
    m_offlineBulkImport=false;
    ui->tablePackets->setUpdatesEnabled(true);
    if(!loaded){
        m_offlineRecentPackets.clear();
        log("导入抓包文件失败: "+error);
        return;
    }
    renderOfflineRecentPackets();
    refreshRealtimeTcpAnalysis();
    rebuildProtocolEvidenceFromStreams();
    updateStats(m_offline->stats());
    renderFieldDiagnosis();
}


void MainWindow::convertTcpdumpTextToPcap(){
    if(m_capCtrl->isRunning()){log(QStringLiteral("请先停止在线抓包，再转换 tcpdump 文本"));return;}
    const QString sourcePath=QFileDialog::getOpenFileName(this,QStringLiteral("选择 tcpdump/PuTTY 文本日志"),QString(),QStringLiteral("tcpdump/PuTTY 日志 (*.log *.txt);;所有文件 (*.*)"));
    if(sourcePath.isEmpty())return;

    QFile source(sourcePath);
    if(!source.open(QIODevice::ReadOnly)){log(QStringLiteral("读取 tcpdump 文本失败: ")+source.errorString());return;}

    TcpdumpTextConversionResult converted;
    QString error;
    const QDate fallbackDate=QFileInfo(sourcePath).lastModified().date();
    if(!TcpdumpTextPcapConverter::convert(source.readAll(),&converted,&error,fallbackDate)){
        log(QStringLiteral("tcpdump文本→PCAP失败: ")+error);
        for(const QString& warning:converted.warnings)log(QStringLiteral("转换提示: ")+warning);
        return;
    }

    const QFileInfo sourceInfo(sourcePath);
    const QString suggested=sourceInfo.dir().filePath(sourceInfo.completeBaseName()+QStringLiteral("_converted.pcap"));
    const QString pcapPath=QFileDialog::getSaveFileName(this,QStringLiteral("保存转换后的 PCAP"),suggested,QStringLiteral("PCAP (*.pcap)"));
    if(pcapPath.isEmpty())return;

    QSaveFile output(pcapPath);
    if(!output.open(QIODevice::WriteOnly)){log(QStringLiteral("创建 PCAP 失败: ")+output.errorString());return;}
    if(output.write(converted.pcapData)!=converted.pcapData.size() || !output.commit()){
        log(QStringLiteral("保存 PCAP 失败: ")+output.errorString());
        return;
    }

    for(const QString& warning:converted.warnings)log(QStringLiteral("转换提示: ")+warning);
    log(QStringLiteral("tcpdump文本→PCAP完成: 恢复 %1 包，跳过不完整 %2 包，其他跳过 %3 包")
        .arg(converted.packetCount).arg(converted.truncatedPacketCount).arg(converted.skippedPacketCount));

    m_fieldCaptureMode=FieldCaptureMode::None;
    m_fieldChannelAnalyzer.reset();
    m_protocolEvidence=ProtocolEvidence{};
    if(!m_offline->loadData(converted.pcapData,&error,pcapPath)){
        log(QStringLiteral("转换成功，但自动导入 PCAP 失败: ")+error);
        return;
    }
    clearPacketView();
    ui->mainTabs->setCurrentWidget(ui->tabRealtimeCapture);
    m_offline->startReplay(OfflinePcapController::ReplaySpeed::Fastest);
    statusBar()->showMessage(QStringLiteral("已转换并导入 %1 个数据包").arg(converted.packetCount),5000);
}

void MainWindow::replayPcap(){
    if(m_capCtrl->isRunning()){log("请先停止在线抓包，再回放离线抓包");return;}
    m_fieldCaptureMode=FieldCaptureMode::None;
    m_fieldChannelAnalyzer.reset();
    if(!m_offline->isLoaded()){log("请先导入抓包文件");return;}
    clearPacketView();
    m_protocolEvidence=ProtocolEvidence{};
    ui->mainTabs->setCurrentWidget(ui->tabRealtimeCapture);
    OfflinePcapController::ReplaySpeed speed=OfflinePcapController::ReplaySpeed::Fastest;
    switch(ui->comboReplaySpeed->currentIndex()){
    case 0:speed=OfflinePcapController::ReplaySpeed::X1;break;
    case 1:speed=OfflinePcapController::ReplaySpeed::X5;break;
    case 2:speed=OfflinePcapController::ReplaySpeed::X10;break;
    default:speed=OfflinePcapController::ReplaySpeed::Fastest;break;
    }
    m_offline->startReplay(speed);
}

void MainWindow::stopReplay(){m_offline->stopReplay();}

void MainWindow::appendPacket(const ParsedPacket& p){
    m_packetChannelAnalyzer.consume(p);
    if(p.protocol==QStringLiteral("TCP") && p.tcpPayloadLength>0 && !p.payload.isEmpty()){
        m_tcpReassembler.consume(p);
        // Re-parsing every accumulated TCP byte stream for every packet is O(n^2) over a
        // long capture. Coalesce bursts while keeping protocol/IEC104 UI updates near-real-time.
        if(!m_offlineBulkImport && m_protocolRefreshTimer && !m_protocolRefreshTimer->isActive())m_protocolRefreshTimer->start();
    }
    if(m_offlineBulkImport){
        ++m_packetNo;
        constexpr int MaxOfflineVisiblePackets=20000;
        if(m_offlineRecentPackets.size()<MaxOfflineVisiblePackets)m_offlineRecentPackets.append(p);
        else{
            m_offlineRecentPackets[m_offlineRecentWriteIndex]=p;
            m_offlineRecentWriteIndex=(m_offlineRecentWriteIndex+1)%MaxOfflineVisiblePackets;
            m_offlineRecentWrapped=true;
        }
        return;
    }
    refreshRealtimeTcpAnalysis();
    if(m_fieldChannelAnalyzer && m_capCtrl->isRunning()){
        m_fieldChannelAnalyzer->consume(p);
        if(m_fieldCaptureMode==FieldCaptureMode::Master){
            m_masterChannelEvidence=m_fieldChannelAnalyzer->evidence();
            const FieldDiagnosticConfig cfg=currentFieldConfig();
            m_actualMasterSessions=ChannelAnalyzer::actualPeerSessions(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
            m_actualMasterIps=ChannelAnalyzer::actualPeerIps(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
            if(p.protocol==QStringLiteral("TCP") && p.tcpPayloadLength>0 &&
               (p.sourcePort==cfg.masterPort || p.destinationPort==cfg.masterPort)){
                const bool fromMaster=!m_actualMasterSessions.isEmpty()
                    ? ChannelAnalyzer::packetFromActualPeer(p,m_actualMasterSessions,cfg.masterRole,cfg.masterPort)
                    : ChannelAnalyzer::packetFromActualPeer(p,m_actualMasterIps,cfg.masterRole,cfg.masterPort);
                if(fromMaster){
                    if(m_masterDownstreamPayloads.size()<50)m_masterDownstreamPayloads<<p;
                }else{
                    ++m_masterUpstreamPayloadPackets;
                }
            }
        }
        if(m_fieldCaptureMode==FieldCaptureMode::TerminalEthernet) m_terminalChannelEvidence=m_fieldChannelAnalyzer->evidence();
        renderFieldDiagnosis();
    }
    int row=ui->tablePackets->rowCount();
    if(row>=20000){ui->tablePackets->removeRow(0);row--;}
    ui->tablePackets->insertRow(row);
    auto set=[this,row](int c,const QString& v){ui->tablePackets->setItem(row,c,new QTableWidgetItem(v));};
    set(0,QString::number(++m_packetNo));
    set(1,p.timestamp.toLocalTime().toString(QStringLiteral("HH:mm:ss.zzz")));
    set(2,p.sourceIp+(p.sourcePort?QStringLiteral(":")+QString::number(p.sourcePort):QString()));
    set(3,p.destinationIp+(p.destinationPort?QStringLiteral(":")+QString::number(p.destinationPort):QString()));
    set(4,p.protocol);
    const quint32 displayLength=(p.protocol==QStringLiteral("TCP"))?p.tcpPayloadLength:p.payload.isEmpty()?p.ipTotalLength:quint32(p.payload.size());
    set(5,QString::number(displayLength));
    set(6,p.summary);
    if(ui->comboTerminalTransport->currentIndex()!=0)appendCaptureTimeline(QStringLiteral("网络/%1").arg(m_activeCaptureIface.isEmpty()?captureInterfaceText():m_activeCaptureIface),QStringLiteral("%1 %2 -> %3  %4").arg(p.protocol,p.sourceIp,p.destinationIp,p.summary).left(260));
    if(auto* item=ui->tablePackets->item(row,0)){
        item->setData(Qt::UserRole,packetDetailText(p));
        item->setData(Qt::UserRole+1,QVariant::fromValue(p));
    }
    refreshCaptureQuickFilter();
    if(ui->checkFollowLatestPacket && ui->checkFollowLatestPacket->isChecked()){
        ui->tablePackets->setCurrentCell(row,0);
        ui->tablePackets->scrollToBottom();
        showPacketDetail(row);
    }
}


void MainWindow::renderOfflineRecentPackets()
{
    ui->tablePackets->setUpdatesEnabled(false);
    ui->tablePackets->setRowCount(0);
    const int count=m_offlineRecentPackets.size();
    const quint64 firstNo=m_packetNo>=quint64(count)?m_packetNo-quint64(count)+1:1;
    auto packetAt=[this,count](int logical)->const ParsedPacket&{
        if(!m_offlineRecentWrapped)return m_offlineRecentPackets.at(logical);
        const int physical=(m_offlineRecentWriteIndex+logical)%count;
        return m_offlineRecentPackets.at(physical);
    };
    for(int i=0;i<count;++i){
        const ParsedPacket& p=packetAt(i);
        const int row=ui->tablePackets->rowCount();ui->tablePackets->insertRow(row);
        auto set=[this,row](int c,const QString& v){ui->tablePackets->setItem(row,c,new QTableWidgetItem(v));};
        set(0,QString::number(firstNo+quint64(i)));
        set(1,p.timestamp.toLocalTime().toString(QStringLiteral("HH:mm:ss.zzz")));
        set(2,p.sourceIp+(p.sourcePort?QStringLiteral(":")+QString::number(p.sourcePort):QString()));
        set(3,p.destinationIp+(p.destinationPort?QStringLiteral(":")+QString::number(p.destinationPort):QString()));
        set(4,p.protocol);
        const quint32 displayLength=(p.protocol==QStringLiteral("TCP"))?p.tcpPayloadLength:p.payload.isEmpty()?p.ipTotalLength:quint32(p.payload.size());
        set(5,QString::number(displayLength));set(6,p.summary);
        if(auto* item=ui->tablePackets->item(row,0)){item->setData(Qt::UserRole,packetDetailText(p));item->setData(Qt::UserRole+1,QVariant::fromValue(p));}
        if((i%250)==0)QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,5);
    }
    ui->tablePackets->setUpdatesEnabled(true);
    if(count>0){ui->tablePackets->setCurrentCell(count-1,0);ui->tablePackets->scrollToBottom();showPacketDetail(count-1);}
    refreshCaptureQuickFilter();
}

FieldDiagnosticConfig MainWindow::currentFieldConfig() const{
    FieldDiagnosticConfig cfg;
    cfg.masterIp=ui->editMasterIp->text().trimmed();
    cfg.masterPort=quint16(ui->spinMasterPort->value());
    cfg.masterRole=ui->comboMasterRole->currentIndex()==0?EndpointRole::Client:EndpointRole::Server;
    cfg.terminalTransport=ui->comboTerminalTransport->currentIndex()==0 ? TerminalTransport::Ethernet : TerminalTransport::Serial;
    cfg.terminalIp=ui->editTerminalIp->text().trimmed();
    cfg.terminalPort=quint16(ui->spinTerminalPort->value());
    cfg.terminalRole=ui->comboTerminalRole->currentIndex()==0?EndpointRole::Client:EndpointRole::Server;
    cfg.expectedConnectionSeconds=ui->spinExpectedConnectionSeconds->value();
    return cfg;
}

bool MainWindow::prepareCaptureStorage(const QString& prefix){
    if(!ui->checkDirectSave->isChecked()){
        m_capCtrl->clearDirectSave();
        return true;
    }
    const QString path=QFileDialog::getSaveFileName(
        this,QStringLiteral("PC端保存PCAP"),
        QStringLiteral("%1_%2.pcap").arg(prefix,QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        QStringLiteral("PCAP (*.pcap)"));
    if(path.isEmpty())return false;
    QString error;
    if(!m_capCtrl->setDirectSavePath(path,&error)){
        log(QStringLiteral("无法创建PCAP文件: ")+error);
        return false;
    }
    return true;
}


void MainWindow::loadConnectionHistory(){
    QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
    const QStringList history=settings.value(QStringLiteral("connection/history")).toStringList();
    ui->comboConnectionHistory->clear();
    ui->comboConnectionHistory->addItems(history);
    const QString last=settings.value(QStringLiteral("connection/lastHost")).toString();
    if(!last.isEmpty())ui->editHost->setText(last);
}

void MainWindow::saveConnectionHistory(){
    const QString host=ui->editHost->text().trimmed();
    if(host.isEmpty())return;
    QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
    QStringList history=settings.value(QStringLiteral("connection/history")).toStringList();
    history.removeAll(host);history.prepend(host);
    while(history.size()>20)history.removeLast();
    settings.setValue(QStringLiteral("connection/history"),history);
    settings.setValue(QStringLiteral("connection/lastHost"),host);
    ui->comboConnectionHistory->clear();ui->comboConnectionHistory->addItems(history);
}

bool MainWindow::controlCommandBusy() const{
    return (m_control&&m_control->isBusy()) || (m_discovery&&m_discovery->isRunning()) ||
           (m_diag&&m_diag->isRunning()) || (m_fieldDiag&&m_fieldDiag->isBusy());
}

void MainWindow::displayDeviceDiscovery(const DeviceDiscoveryResult& result){
    m_discoveredWanIfname=result.wanIfname;
    m_discoveredWanIp=result.wanIp;
    m_discoveredWanIpSource=result.wanIpSource;
    m_discoveredInterfaces=result.interfaces;
    ui->tableInterfaces->setRowCount(0);
    for(const auto& info:result.interfaces){
        if(!info.up)continue;
        const int row=ui->tableInterfaces->rowCount();ui->tableInterfaces->insertRow(row);
        ui->tableInterfaces->setItem(row,0,new QTableWidgetItem(info.name));
        ui->tableInterfaces->setItem(row,1,new QTableWidgetItem(info.ipv4));
        ui->tableInterfaces->setItem(row,2,new QTableWidgetItem(QStringLiteral("UP")));
    }
    rebuildCaptureInterfaceChoices();
    const int activeCaptureMode=ui->comboCaptureMode->currentIndex();
    if((activeCaptureMode==0 || activeCaptureMode==1) && !result.wanIfname.isEmpty())setCaptureInterfaceText(result.wanIfname);
    else if(activeCaptureMode==2 && ui->comboTerminalTransport->currentIndex()==0)setCaptureInterfaceText(autoTerminalCaptureInterface());
    else if(captureInterfaceText().isEmpty() && !result.wanIfname.isEmpty())setCaptureInterfaceText(result.wanIfname);
    QString text;
    if(!result.wanIfname.isEmpty())text=QStringLiteral("检测完成：WAN 接口 %1").arg(result.wanIfname);
    else text=QStringLiteral("未识别到可用 WAN 接口，检测已停止");
    if(!result.wanIp.isEmpty())text+=QStringLiteral("，IP %1（来源：%2）").arg(result.wanIp,result.wanIpSource.isEmpty()?QStringLiteral("未知"):result.wanIpSource);
    if(!result.backupWanIp.isEmpty() && !result.wanIpSource.contains(QStringLiteral("bkup_wan_ipaddr")))
        text+=QStringLiteral("；备用 bkup_wan_ipaddr=%1").arg(result.backupWanIp);
    if(result.usingBackupCard)text+=QStringLiteral("；当前使用备卡 NVRAM");
    ui->labelAutoDetectStatus->setText(text);
    ui->labelWanSummary->setText(result.wanIfname.isEmpty()?QStringLiteral("WAN：未识别"):QStringLiteral("WAN：%1  %2  [%3]").arg(result.wanIfname,result.wanIp.isEmpty()?QStringLiteral("未获取IP"):result.wanIp,result.wanIpSource.isEmpty()?QStringLiteral("无IP来源"):result.wanIpSource));
    const bool hasWan=!result.wanIfname.isEmpty();
    const bool hasIp=ConnectivityProbe::isUsableWanIpv4(result.wanIp);
    if(hasWan)m_lastStatus.wanIfname=result.wanIfname;
    if(ConnectivityProbe::isUsableWanIpv4(result.wanNvramIp))m_lastStatus.nvramPrimaryWanIp=result.wanNvramIp;
    if(ConnectivityProbe::isUsableWanIpv4(result.backupWanIp))m_lastStatus.backupWanIp=result.backupWanIp;
    if(ConnectivityProbe::isUsableWanIpv4(result.commWanIp))m_lastStatus.commWanIp=result.commWanIp;
    if(hasIp){
        m_lastStatus.wanIp=result.wanIp;
        m_lastStatus.wanIpFromNvramSnapshot=false;
        m_lastStatus.wanIpSource=result.wanIpSource;
    }
    m_lastStatus.wanInterfaceStateKnown=result.wanInterfaceStateKnown;
    m_lastStatus.wanInterfaceUp=result.wanInterfaceUp;
    m_lastStatus.defaultRouteChecked=result.defaultRouteChecked;
    m_lastStatus.defaultRoutePresent=result.defaultRoutePresent;
    m_lastStatus.defaultGateway=result.defaultGateway;
    m_lastStatus.defaultRouteInterface=result.defaultRouteInterface;
    m_lastStatus.moduleProbeAttempted=result.moduleProbeAttempted;
    m_lastStatus.moduleProbeCompleted=result.moduleProbeCompleted;
    if(!result.simStatus.isEmpty()){
        m_lastStatus.simStatus=result.simStatus;
        m_lastStatus.simStatusFromNvram=result.simStatusFromNvram;
        if(m_lastStatus.simStatus.compare(QStringLiteral("READY"),Qt::CaseInsensitive)==0)m_lastStatus.simCardRaw=QStringLiteral("simok");
    }
    if(result.rsrp!=999)m_lastStatus.rsrp=result.rsrp;
    if(result.sinr!=999)m_lastStatus.sinr=result.sinr;
    if(!result.nvramNetwork.isEmpty())m_lastStatus.radioAccessMode=result.nvramNetwork;
    m_lastStatus.activeWanPath=result.usingBackupCard?QStringLiteral("backup"):QStringLiteral("primary");
    if(result.commModuleStatus>=0)m_lastStatus.commModuleStatus=result.commModuleStatus;
    if(result.commDialStatus>=0)m_lastStatus.commDialStatus=result.commDialStatus;
    if(result.wanUp>=0)m_lastStatus.wanUp=result.wanUp;
    if(result.backupWanUp>=0)m_lastStatus.backupWanUp=result.backupWanUp;
    if(!result.cpinRaw.isEmpty())m_lastStatus.cpinRaw=result.cpinRaw;
    if(!result.cereg.isEmpty())m_lastStatus.cereg=result.cereg;
    if(!result.cgreg.isEmpty())m_lastStatus.cgreg=result.cgreg;
    if(!result.creg.isEmpty())m_lastStatus.creg=result.creg;
    if(!result.c5greg.isEmpty())m_lastStatus.c5greg=result.c5greg;
    if(result.cgatt>=0)m_lastStatus.cgatt=result.cgatt;
    if(result.csq>=0)m_lastStatus.csq=result.csq;
    if(!result.operatorName.isEmpty())m_lastStatus.operatorName=result.operatorName;
    if(result.operatorAccessTechnology>=0)m_lastStatus.operatorAccessTechnology=result.operatorAccessTechnology;
    if(!result.atErrors.isEmpty())m_lastStatus.evidence<<result.atErrors;
    if(result.moduleAtResponsive || !result.moduleModel.isEmpty()){
        m_lastStatus.moduleAtResponsive=m_lastStatus.moduleAtResponsive||result.moduleAtResponsive;
        m_lastStatus.moduleDetected=true;
        if(!result.moduleControlDevice.isEmpty())m_lastStatus.moduleControlDevice=result.moduleControlDevice;
        if(!result.moduleModel.isEmpty())m_lastStatus.moduleName=result.moduleModel;
        if(!result.moduleFirmware.isEmpty())m_lastStatus.firmware=result.moduleFirmware;
        const LayerState moduleState=(result.moduleAtResponsive || result.commModuleStatus==1)?LayerState::Normal:LayerState::Unknown;
        const QString moduleValue=moduleCardText(result.moduleModel,moduleState);
        setStatusCard(ui->labelCardModule,QStringLiteral("模组"),moduleValue,moduleState);
        QStringList moduleTip;
        moduleTip<<QStringLiteral("来源：%1").arg(result.moduleFromNvram?QStringLiteral("NVRAM优先读取"):QStringLiteral("AT补充识别"));
        if(result.moduleFromNvram && result.moduleAtResponsive)
            moduleTip<<QStringLiteral("AT口已响应；NVRAM 已提供模组信息，未用 AT 覆盖显示值");
        if(!result.moduleAtResponsive && result.commModuleStatus>=0)moduleTip<<QStringLiteral("comm_module_status=%1").arg(result.commModuleStatus);
        if(!result.moduleManufacturer.isEmpty())moduleTip<<QStringLiteral("厂商：%1").arg(result.moduleManufacturer);
        if(!result.moduleModel.isEmpty())moduleTip<<QStringLiteral("型号：%1").arg(result.moduleModel);
        if(!result.moduleFirmware.isEmpty())moduleTip<<QStringLiteral("固件：%1").arg(result.moduleFirmware);
        if(!result.moduleControlDevice.isEmpty())moduleTip<<QStringLiteral("AT口：%1").arg(result.moduleControlDevice);
        if(!result.operatorName.isEmpty())moduleTip<<QStringLiteral("运营商：%1").arg(result.operatorName);
        if(result.csq>=0)moduleTip<<QStringLiteral("CSQ：%1").arg(result.csq);
        if(result.cgatt>=0)moduleTip<<QStringLiteral("CGATT：%1").arg(result.cgatt);
        if(!result.atErrors.isEmpty())moduleTip<<QStringLiteral("AT提示：%1").arg(result.atErrors.join(QStringLiteral("；")));
        ui->labelCardModule->setToolTip(moduleTip.join(QLatin1Char('\n')));
        text+=QStringLiteral("；模组 %1").arg(moduleValue);
        if(!result.moduleControlDevice.isEmpty())text+=QStringLiteral("（%1）").arg(result.moduleControlDevice);
        ui->labelAutoDetectStatus->setText(text);
    }else if(!result.moduleProbeAttempted){
        setStatusCard(ui->labelCardModule,QStringLiteral("模组"),QStringLiteral("未测试"),LayerState::NotTested);
        ui->labelCardModule->setToolTip(QStringLiteral("NVRAM 未返回模组标识，且 WAN 接口未识别，因此未继续 AT 探测"));
    }else{
        setStatusCard(ui->labelCardModule,QStringLiteral("模组"),QStringLiteral("未识别"),LayerState::Unknown);
        ui->labelCardModule->setToolTip(QStringLiteral("未从候选 ttyUSB/ttyACM 端口获得有效 AT 应答"));
    }
    // A completed base discovery is itself diagnostic evidence, including a
    // negative WAN result.  Keep the layered report synchronized even when
    // module probing was intentionally skipped.
    m_lastDiagnosis=DiagnosisEngine::diagnose(m_lastStatus);
    setStatusCard(ui->labelCardWan,QStringLiteral("WAN"),hasWan?result.wanIfname:QStringLiteral("未识别"),hasWan?LayerState::Normal:LayerState::Unknown);
    setStatusCard(ui->labelCardWanIp,QStringLiteral("WAN IP"),hasIp?result.wanIp:QStringLiteral("未识别"),hasIp?LayerState::Normal:LayerState::Unknown);
    renderFieldDiagnosis();
    updateCaptureModeUi();
    log(text);
}

void MainWindow::showModuleLog(){
    RemoteConnectionParams p{ui->editHost->text().trimmed(),quint16(ui->spinPort->value()),ui->editUser->text(),ui->editPassword->text()};
    auto* dialog=new RemoteToolDialog(RemoteToolDialog::Mode::ModuleLog,p,QString(),this);
    dialog->show();
}

void MainWindow::showCommandWindow(){
    RemoteConnectionParams p{ui->editHost->text().trimmed(),quint16(ui->spinPort->value()),ui->editUser->text(),ui->editPassword->text()};
    auto* dialog=new RemoteToolDialog(RemoteToolDialog::Mode::Command,p,QString(),this);
    dialog->show();
}

void MainWindow::showPingWindow(){
    RemoteConnectionParams p{ui->editHost->text().trimmed(),quint16(ui->spinPort->value()),ui->editUser->text(),ui->editPassword->text()};
    QString target=ui->editMasterIp->text().trimmed();
    if(!ConnectivityProbe::isValidIpv4(target))target=QStringLiteral("223.5.5.5");
    auto* dialog=new RemoteToolDialog(RemoteToolDialog::Mode::Ping,p,target,this);
    dialog->show();
}

void MainWindow::oneClickDiagnosis(){
    if(!m_controlLoggedIn || !captureTransportReady()){
        log(QStringLiteral("一键现场诊断需要先登录路由后台"));
        return;
    }
    if(m_capCtrl&&m_capCtrl->isRunning()){
        log(QStringLiteral("已有抓包正在运行，请先停止后再执行一键现场诊断"));
        return;
    }
    for(CaptureSessionWidget* session:m_captureSessions){
        if(session && session->isRunning()){log(QStringLiteral("已有独立抓包窗口正在运行，请先停止后再执行一键现场诊断"));return;}
    }
    if(controlCommandBusy()){
        log(QStringLiteral("控制通道正在执行其他命令，请等待完成"));
        return;
    }
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    FieldWorkflowConfig workflowCfg;
    workflowCfg.masterConfigured=ConnectivityProbe::isValidIpv4(cfg.masterIp)&&cfg.masterPort>0;
    workflowCfg.terminalTransport=cfg.terminalTransport;
    workflowCfg.terminalConfigured=cfg.terminalTransport==TerminalTransport::Serial || (ConnectivityProbe::isValidIpv4(cfg.terminalIp)&&cfg.terminalPort>0);
    workflowCfg.synchronizedEthernetCapture=(cfg.terminalTransport==TerminalTransport::Ethernet && !routerSerialMode());
    if(!workflowCfg.masterConfigured){log(QStringLiteral("无法开始一键现场诊断：请填写有效主站IP和业务端口"));return;}
    if(cfg.terminalTransport==TerminalTransport::Ethernet&&!workflowCfg.terminalConfigured){log(QStringLiteral("无法开始一键现场诊断：网口模式请填写有效终端IP和端口"));return;}
    if(cfg.masterRole==cfg.terminalRole){
        const QString roleText=cfg.masterRole==EndpointRole::Client?QStringLiteral("双方都配置为客户端，可能同时主动连接导致没有监听端"):QStringLiteral("双方都配置为服务端，可能没有任何一方主动发起TCP连接");
        log(QStringLiteral("拓扑提醒：%1；一键诊断仍继续，但60秒无连接时请优先核对主站/终端角色").arg(roleText));
        statusBar()->showMessage(QStringLiteral("拓扑提醒：主站和终端角色配置相同"),8000);
    }

    saveFieldHistory();
    m_lastStatus=WanStatus{};
    m_lastDiagnosis=DiagnosisResult{};
    m_lastReport.clear();
    m_masterPing=PingResult{};m_terminalPing=PingResult{};
    m_masterPingAttempted=false;m_terminalPingAttempted=false;
    m_masterChannelEvidence=ChannelEvidence{};m_terminalChannelEvidence=ChannelEvidence{};
    m_protocolEvidence=ProtocolEvidence{};
    m_actualMasterIps.clear();m_actualMasterSessions.clear();m_masterDownstreamPayloads.clear();m_masterUpstreamPayloadPackets=0;
    m_dualCaptureCorrelator.reset();m_syncCaptureSharedInterface=false;
    m_fieldChannelAnalyzer.reset();m_fieldCaptureMode=FieldCaptureMode::None;m_fieldPingMode=FieldPingMode::None;
    clearPacketView();
    ui->mainTabs->setCurrentWidget(ui->tabFieldDiagnosis);
    renderFieldDiagnosis();

    QString error;
    if(!m_workflow->start(workflowCfg,&error)){
        log(QStringLiteral("无法开始一键现场诊断：%1").arg(error));
        return;
    }
    log(QStringLiteral("开始一键现场诊断：读取接口/WAN → WAN分层 → 主站Ping/TCP → 终端Ping/TCP → 业务数据分析"));
    updateConnectionUi();
}

void MainWindow::cancelOneClickDiagnosis(){
    if(!m_workflow||!m_workflow->isRunning())return;
    if(m_workflowCaptureTimer)m_workflowCaptureTimer->stop();
    if(m_diag&&m_diag->isRunning())m_diag->cancel();
    if(m_capCtrl&&m_capCtrl->isRunning())m_capCtrl->stop();
    if(m_syncWorkflowCaptureActive)stopSynchronizedWorkflowCapture();
    m_workflow->cancel();
    m_fieldPingMode=FieldPingMode::None;
    log(QStringLiteral("已停止一键现场诊断"));
    updateConnectionUi();renderFieldDiagnosis();
}

void MainWindow::handleWorkflowAction(FieldWorkflowAction action){
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    switch(action){
    case FieldWorkflowAction::DiscoverDevice:
        if(m_discovery->isRunning()){
            log(QStringLiteral("一键诊断：等待当前接口自动检测完成"));
        }else{
            log(QStringLiteral("一键诊断：读取WAN接口和WAN/SIM IP"));
            m_discovery->start();
        }
        break;
    case FieldWorkflowAction::DiagnoseWan:
        log(QStringLiteral("一键诊断：分析模组、SIM、注册和WAN状态"));
        // Reaching this step proves a usable WAN interface was found.  Only now
        // start the auxiliary live log connection; a failed WAN inventory stops
        // cleanly without opening another automatic detection stream.
        startBackgroundModuleLog();
        m_diag->startDiagnosis();
        break;
    case FieldWorkflowAction::PingMaster:
        log(QStringLiteral("一键诊断：Ping主站 %1").arg(cfg.masterIp));
        m_masterPingAttempted=true;m_masterPing=PingResult{};m_fieldPingMode=FieldPingMode::Master;
        m_fieldDiag->setConfig(cfg);m_fieldDiag->pingMaster();
        break;
    case FieldWorkflowAction::CaptureMaster:
        startWorkflowCapture(FieldCaptureMode::Master);
        break;
    case FieldWorkflowAction::PingTerminal:
        log(QStringLiteral("一键诊断：Ping终端 %1").arg(cfg.terminalIp));
        m_terminalPingAttempted=true;m_terminalPing=PingResult{};m_fieldPingMode=FieldPingMode::TerminalEthernet;
        m_fieldDiag->setConfig(cfg);m_fieldDiag->pingTerminal();
        break;
    case FieldWorkflowAction::CaptureTerminal:
        startWorkflowCapture(FieldCaptureMode::TerminalEthernet);
        break;
    }
    renderFieldDiagnosis();
}


QString MainWindow::autoTerminalCaptureInterface() const
{
    const QString terminalIp=currentFieldConfig().terminalIp;
    if(ConnectivityProbe::isValidIpv4(terminalIp)){
        for(const auto& info:m_discoveredInterfaces){
            if(info.name!=QStringLiteral("br0") && info.name!=QStringLiteral("br0:1"))continue;
            if(!info.up || !ConnectivityProbe::isValidIpv4(info.ipv4) || !ConnectivityProbe::isValidIpv4(info.netmask))continue;
            if(ConnectivityProbe::sameIpv4Subnet(terminalIp,info.ipv4,info.netmask))return info.name;
        }
    }
    for(const QString& preferred:QStringList{QStringLiteral("br0"),QStringLiteral("br0:1")})
        for(const auto& info:m_discoveredInterfaces)if(info.name==preferred && info.up)return info.name;
    for(const auto& info:m_discoveredInterfaces){
        if(!info.up || info.name.isEmpty() || info.name==m_discoveredWanIfname)continue;
        if(!info.ipv4.isEmpty())return info.name;
    }
    return QStringLiteral("br0");
}

bool MainWindow::validateTerminalLanSubnet(const QString& terminalIp,QString* reason) const
{
    if(reason)reason->clear();
    if(!ConnectivityProbe::isValidIpv4(terminalIp))return true; // validity is reported by the caller

    QStringList checked;
    bool haveLanSubnet=false;
    for(const auto& info:m_discoveredInterfaces){
        if(info.name!=QStringLiteral("br0") && info.name!=QStringLiteral("br0:1"))continue;
        if(!info.up || !ConnectivityProbe::isValidIpv4(info.ipv4) || !ConnectivityProbe::isValidIpv4(info.netmask))continue;
        haveLanSubnet=true;
        checked<<QStringLiteral("%1=%2/%3").arg(info.name).arg(info.ipv4).arg(info.netmask);
        if(ConnectivityProbe::sameIpv4Subnet(terminalIp,info.ipv4,info.netmask))return true;
    }
    if(!haveLanSubnet)return true; // no reliable br0/br0:1 subnet evidence: do not create a false configuration error

    if(reason){
        *reason=QStringLiteral("终端IP配置错误，请检查配置：终端IP %1 与路由器 LAN 网段不一致（%2）")
            .arg(terminalIp,checked.join(QStringLiteral("；")));
    }
    return false;
}

void MainWindow::consumeSynchronizedMasterPacket(const ParsedPacket& p)
{
    if(!m_syncMasterAnalyzer)return;
    if(!m_syncCaptureSharedInterface)m_dualCaptureCorrelator.consume(CaptureSide::Wan,p);
    m_syncMasterAnalyzer->consume(p);
    m_masterChannelEvidence=m_syncMasterAnalyzer->evidence();
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    m_actualMasterSessions=ChannelAnalyzer::actualPeerSessions(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
    m_actualMasterIps=ChannelAnalyzer::actualPeerIps(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
    if(p.protocol==QStringLiteral("TCP") && p.tcpPayloadLength>0 && !p.payload.isEmpty() &&
       (p.sourcePort==cfg.masterPort || p.destinationPort==cfg.masterPort)){
        const bool fromMaster=!m_actualMasterSessions.isEmpty()
            ? ChannelAnalyzer::packetFromActualPeer(p,m_actualMasterSessions,cfg.masterRole,cfg.masterPort)
            : ChannelAnalyzer::packetFromActualPeer(p,m_actualMasterIps,cfg.masterRole,cfg.masterPort);
        if(fromMaster){
            if(m_masterDownstreamPayloads.size()<50)m_masterDownstreamPayloads<<p;
        }else ++m_masterUpstreamPayloadPackets;
        const ProtocolEvidence part=ProtocolDiagnosis::analyzeTcpPayload(p.payload);
        if(part.gridFrames||part.iec101Frames||part.iec104Frames)ProtocolDiagnosis::merge(m_protocolEvidence,part);
    }
    renderFieldDiagnosis();
}

void MainWindow::startSynchronizedWorkflowCapture()
{
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    if(cfg.terminalTransport==TerminalTransport::Ethernet){
        QString subnetError;
        if(!validateTerminalLanSubnet(cfg.terminalIp,&subnetError)){
            m_workflow->operationFailed(subnetError);
            return;
        }
    }
    const QString masterIface=captureInterfaceText();
    const QString terminalIface=autoTerminalCaptureInterface();
    const QString masterFilter=FieldDiagnosticController::buildMasterFilter(cfg);
    const QString terminalFilter=FieldDiagnosticController::buildTerminalFilter(cfg);
    if(masterIface.isEmpty()||masterFilter.isEmpty()||terminalFilter.isEmpty()){
        m_workflow->operationFailed(QStringLiteral("同步抓包参数不完整：请确认WAN接口、终端IP和业务端口"));
        return;
    }

    m_masterChannelEvidence=ChannelEvidence{};
    m_terminalChannelEvidence=ChannelEvidence{};
    m_actualMasterIps.clear();m_actualMasterSessions.clear();m_masterDownstreamPayloads.clear();m_masterUpstreamPayloadPackets=0;
    ChannelCriteria masterCriteria;masterCriteria.peerIp.clear();masterCriteria.peerPort=cfg.masterPort;masterCriteria.requirePeerPort=true;
    ChannelCriteria terminalCriteria;terminalCriteria.peerIp=cfg.terminalIp;terminalCriteria.peerPort=cfg.terminalPort;terminalCriteria.requirePeerPort=true;
    m_syncMasterAnalyzer=std::make_unique<ChannelAnalyzer>(masterCriteria);
    m_syncTerminalAnalyzer=std::make_unique<ChannelAnalyzer>(terminalCriteria);
    m_syncExpectedSessions=0;m_syncStartedSessions=0;m_syncStoppedSessions=0;m_syncWorkflowCaptureActive=true;
    m_syncCaptureSharedInterface=(masterIface==terminalIface);m_dualCaptureCorrelator.reset();
    m_workflowMasterCaptureSession=nullptr;m_workflowTerminalCaptureSession=nullptr;

    auto bindCommon=[this](CaptureSessionWidget* session){
        if(!session)return;
        ++m_syncExpectedSessions;
        connect(session,&CaptureSessionWidget::captureSessionStarted,this,[this]{
            if(!m_syncWorkflowCaptureActive)return;
            ++m_syncStartedSessions;
            if(m_syncStartedSessions==m_syncExpectedSessions && m_workflowCaptureTimer){
                const FieldDiagnosticConfig cfg=currentFieldConfig();
                const int seconds=qMax(ui->spinAutoCaptureSeconds->value(),cfg.expectedConnectionSeconds);
                log(QStringLiteral("一键诊断：终端侧/主站侧同步抓包均已启动，实时观察 %1 秒").arg(seconds));
                m_workflowCaptureTimer->start(seconds*1000);
            }
        });
        connect(session,&CaptureSessionWidget::captureSessionStopped,this,[this]{
            if(!m_syncWorkflowCaptureActive)return;
            ++m_syncStoppedSessions;
            completeSynchronizedWorkflowCaptureIfReady();
        });
        connect(session,&CaptureSessionWidget::captureSessionFailed,this,[this](const QString& reason){
            if(m_syncWorkflowCaptureActive)failSynchronizedWorkflowCapture(reason);
        });
        connect(session,&CaptureSessionWidget::captureSessionClosing,this,[this]{
            if(m_syncWorkflowCaptureActive)failSynchronizedWorkflowCapture(QStringLiteral("同步抓包窗口被关闭"));
        });
    };

    if(masterIface==terminalIface || routerSerialMode()){
        const QString combined=QStringLiteral("(%1) or (%2)").arg(masterFilter,terminalFilter);
        const QString sharedIface=routerSerialMode()?QStringLiteral("any"):masterIface;
        m_syncCaptureSharedInterface=true;
        auto* session=createCaptureSessionWindow(QStringLiteral("一键诊断 · 终端/主站共用接口 %1").arg(sharedIface),sharedIface,combined,false,false);
        if(!session){m_syncWorkflowCaptureActive=false;m_workflow->operationFailed(QStringLiteral("无法创建同步抓包窗口"));return;}
        m_workflowMasterCaptureSession=session;m_workflowTerminalCaptureSession=session;
        bindCommon(session);
        connect(session,&CaptureSessionWidget::packetObserved,this,[this](const ParsedPacket& p){
            if(!m_syncWorkflowCaptureActive)return;
            consumeSynchronizedMasterPacket(p);
            if(m_syncTerminalAnalyzer){m_syncTerminalAnalyzer->consume(p);m_terminalChannelEvidence=m_syncTerminalAnalyzer->evidence();}
        });
        log(routerSerialMode()?QStringLiteral("一键诊断：串口控制模式仅开一个 tcpdump -i any 会话，避免两个抓包任务争用同一 shell"):
                               QStringLiteral("一键诊断：终端侧与主站侧均使用 %1，仅开一个同步抓包会话").arg(masterIface));
        session->startCapture();
    }else{
        auto* master=createCaptureSessionWindow(QStringLiteral("一键诊断 · 主站侧 %1").arg(masterIface),masterIface,masterFilter,false,false);
        auto* terminal=createCaptureSessionWindow(QStringLiteral("一键诊断 · 终端侧 %1").arg(terminalIface),terminalIface,terminalFilter,false,false);
        if(!master||!terminal){
            m_syncWorkflowCaptureActive=false;
            if(master)master->close();
            if(terminal)terminal->close();
            m_workflow->operationFailed(QStringLiteral("无法创建终端/主站同步抓包窗口"));
            return;
        }
        m_workflowMasterCaptureSession=master;m_workflowTerminalCaptureSession=terminal;
        bindCommon(master);bindCommon(terminal);
        connect(master,&CaptureSessionWidget::packetObserved,this,[this](const ParsedPacket& p){if(m_syncWorkflowCaptureActive)consumeSynchronizedMasterPacket(p);});
        connect(terminal,&CaptureSessionWidget::packetObserved,this,[this](const ParsedPacket& p){
            if(!m_syncWorkflowCaptureActive||!m_syncTerminalAnalyzer)return;
            m_dualCaptureCorrelator.consume(CaptureSide::TerminalLan,p);
            m_syncTerminalAnalyzer->consume(p);m_terminalChannelEvidence=m_syncTerminalAnalyzer->evidence();renderFieldDiagnosis();
        });
        log(QStringLiteral("一键诊断：同步启动双点抓包，终端侧=%1，主站侧=%2").arg(terminalIface,masterIface));
        master->startCapture();terminal->startCapture();
    }
}

void MainWindow::failSynchronizedWorkflowCapture(const QString& reason)
{
    if(!m_syncWorkflowCaptureActive)return;
    if(m_workflowCaptureTimer)m_workflowCaptureTimer->stop();
    // Mark inactive before stopping siblings so their asynchronous stopped/error signals
    // cannot recursively fail the workflow a second time.
    m_syncWorkflowCaptureActive=false;
    if(m_workflowMasterCaptureSession&&m_workflowMasterCaptureSession->isRunning())m_workflowMasterCaptureSession->stopCapture();
    if(m_workflowTerminalCaptureSession&&m_workflowTerminalCaptureSession!=m_workflowMasterCaptureSession&&m_workflowTerminalCaptureSession->isRunning())m_workflowTerminalCaptureSession->stopCapture();
    log(QStringLiteral("一键诊断：同步抓包失败，已停止另一侧会话：%1").arg(reason));
    if(m_workflow&&m_workflow->isRunning())m_workflow->operationFailed(QStringLiteral("同步抓包失败：%1").arg(reason));
}

void MainWindow::stopSynchronizedWorkflowCapture()
{
    if(!m_syncWorkflowCaptureActive)return;
    bool any=false;
    if(m_workflowMasterCaptureSession&&m_workflowMasterCaptureSession->isRunning()){m_workflowMasterCaptureSession->stopCapture();any=true;}
    if(m_workflowTerminalCaptureSession && m_workflowTerminalCaptureSession!=m_workflowMasterCaptureSession && m_workflowTerminalCaptureSession->isRunning()){
        m_workflowTerminalCaptureSession->stopCapture();any=true;
    }
    if(!any){m_syncStoppedSessions=m_syncExpectedSessions;completeSynchronizedWorkflowCaptureIfReady();}
}

void MainWindow::completeSynchronizedWorkflowCaptureIfReady()
{
    if(!m_syncWorkflowCaptureActive || m_syncStoppedSessions<m_syncExpectedSessions)return;
    if(m_workflowCaptureTimer)m_workflowCaptureTimer->stop();
    if(m_syncMasterAnalyzer)m_masterChannelEvidence=m_syncMasterAnalyzer->evidence();
    if(m_syncTerminalAnalyzer)m_terminalChannelEvidence=m_syncTerminalAnalyzer->evidence();
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    m_actualMasterSessions=ChannelAnalyzer::actualPeerSessions(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
    m_actualMasterIps=ChannelAnalyzer::actualPeerIps(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
    m_syncWorkflowCaptureActive=false;
    m_workflowMasterCaptureSession=nullptr;m_workflowTerminalCaptureSession=nullptr;
    m_syncMasterAnalyzer.reset();m_syncTerminalAnalyzer.reset();
    renderFieldDiagnosis();
    log(QStringLiteral("一键诊断：终端侧/主站侧同步抓包完成；继续终端Ping并生成双点对比结论"));
    if(m_workflow&&m_workflow->isRunning()&&m_workflow->step()==FieldWorkflowStep::CaptureMaster)m_workflow->masterCaptureCompleted();
}

void MainWindow::startWorkflowCapture(FieldCaptureMode mode){
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    if(mode==FieldCaptureMode::Master && cfg.terminalTransport==TerminalTransport::Ethernet && !routerSerialMode()){
        startSynchronizedWorkflowCapture();
        return;
    }
    ChannelCriteria criteria;
    QString iface;
    QString filter;
    if(mode==FieldCaptureMode::Master){
        iface=captureInterfaceText();
        if(!ConnectivityProbe::isUsableWanInterfaceName(iface)){m_workflow->operationFailed(QStringLiteral("未检测到可用 WAN 接口"));return;}
        filter=FieldDiagnosticController::buildMasterFilter(cfg);
        criteria.peerIp.clear();criteria.peerPort=cfg.masterPort;criteria.requirePeerPort=true;
        log(QStringLiteral("一键诊断：抓主站 %1 秒，接口 %2，过滤 %3")
            .arg(ui->spinAutoCaptureSeconds->value()).arg(iface,filter));
    }else{
        iface=autoTerminalCaptureInterface();
        filter=FieldDiagnosticController::buildTerminalFilter(cfg);
        criteria.peerIp=cfg.terminalIp;criteria.peerPort=cfg.terminalPort;criteria.requirePeerPort=true;
        log(QStringLiteral("一键诊断：抓终端 %1 秒，接口 %2，过滤 %3")
            .arg(ui->spinAutoCaptureSeconds->value()).arg(iface,filter));
    }
    if(!startFieldCapture(mode,iface,filter,criteria,false)){
        m_workflow->operationFailed(QStringLiteral("无法启动%1抓包").arg(mode==FieldCaptureMode::Master?QStringLiteral("主站"):QStringLiteral("终端")));
        return;
    }
    // 计时从真正收到 PCAP 全局头开始，避免把 tcpdump 前置检查时间算进有效抓包时长。
}

void MainWindow::setCaptureTargetVisible(bool visible)
{
    ui->labelCaptureTarget->setVisible(visible);
    ui->editCaptureTarget->setVisible(visible);
    ui->labelCaptureBusinessPort->setVisible(visible);
    ui->spinCapturePort->setVisible(visible);
}

void MainWindow::updateCaptureModeUi(){
    const int mode=ui->comboCaptureMode->currentIndex();
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    if(!m_captureIfaceCombo)return;
    m_captureIfaceCombo->setEnabled(true);
    m_refreshCaptureIfaces->setEnabled(true);
    ui->captureAdvancedPanel->show();
    ui->editFilter->show();
    ui->labelFilter->show();

    if(mode==0){
        setCaptureTargetVisible(false);
        QString detectedWan=!m_discoveredWanIfname.isEmpty()?m_discoveredWanIfname:m_lastStatus.wanIfname;
        if(!ConnectivityProbe::isUsableWanInterfaceName(detectedWan))detectedWan.clear();
        if(captureInterfaceText().isEmpty() || captureInterfaceText()==QStringLiteral("br0"))setCaptureInterfaceText(detectedWan);
        m_captureIfaceCombo->setToolTip(QStringLiteral("WAN抓包默认带入已确认WAN；除 any 外下拉只显示 ifconfig UP接口，any=所有接口"));
    }else if(mode==1){
        setCaptureTargetVisible(true);
        QString detectedWan=!m_discoveredWanIfname.isEmpty()?m_discoveredWanIfname:m_lastStatus.wanIfname;
        if(!ConnectivityProbe::isUsableWanInterfaceName(detectedWan))detectedWan.clear();
        if(captureInterfaceText().isEmpty())setCaptureInterfaceText(detectedWan);
        ui->editCaptureTarget->setText(cfg.masterIp);
        ui->spinCapturePort->setValue(cfg.masterPort);
        FieldDiagnosticConfig temp=cfg;temp.masterIp=ui->editCaptureTarget->text().trimmed();temp.masterPort=quint16(ui->spinCapturePort->value());
        ui->editFilter->setText(FieldDiagnosticController::buildMasterFilter(temp));
    }else if(mode==2){
        const bool ethernet=cfg.terminalTransport==TerminalTransport::Ethernet;
        setCaptureTargetVisible(ethernet);
        if(!ethernet){
            ui->editFilter->clear();
        }else{
            setCaptureInterfaceText(autoTerminalCaptureInterface());
            ui->editCaptureTarget->setText(cfg.terminalIp);
            ui->spinCapturePort->setValue(cfg.terminalPort);
            FieldDiagnosticConfig temp=cfg;temp.terminalTransport=TerminalTransport::Ethernet;temp.terminalIp=ui->editCaptureTarget->text().trimmed();temp.terminalPort=quint16(ui->spinCapturePort->value());
            ui->editFilter->setText(FieldDiagnosticController::buildTerminalFilter(temp));
        }
    }else{
        setCaptureTargetVisible(false);
        m_captureIfaceCombo->setToolTip(QStringLiteral("自定义抓包：除 any 外下拉只显示 ifconfig UP接口；any=所有接口，也可手工输入 tun0 等"));
    }

    const QString iface=captureInterfaceText().isEmpty()?QStringLiteral("未选择接口"):captureInterfaceText();
    const QString filter=ui->editFilter->text().trimmed().isEmpty()?QStringLiteral("全部流量"):ui->editFilter->text().trimmed();
    ui->labelCapturePlan->setText(QStringLiteral("当前：%1 · %2").arg(iface,filter));
}

void MainWindow::updateConnectionUi(){
    const bool workflow=m_workflow&&m_workflow->isRunning();
    const bool controlReady=m_controlLoggedIn;
    const bool captureReady=captureTransportReady();
    const bool ethernet=ui->comboTerminalTransport->currentIndex()==0;
    const bool serialRouter=routerSerialMode();
    const bool anyConnected=m_control->isConnected()||(!serialRouter&&m_capture->isConnected());
    ui->comboRouterConnectionMode->setEnabled(!anyConnected);
    ui->serialSettingsPanel->setEnabled(!anyConnected);
    ui->editHost->setEnabled(!anyConnected);
    ui->spinPort->setEnabled(!anyConnected);
    ui->btnConnect->setEnabled(!anyConnected && (!serialRouter || !ui->comboPcSerialPort->currentData().toString().isEmpty()));
    ui->btnDisconnect->setEnabled(anyConnected||controlReady||m_captureLoggedIn);
    if(auto* compactConnect=ui->groupConnection->findChild<QPushButton*>(QStringLiteral("btnCompactConnect")))compactConnect->setEnabled(ui->btnConnect->isEnabled());
    if(auto* compactDisconnect=ui->groupConnection->findChild<QPushButton*>(QStringLiteral("btnCompactDisconnect")))compactDisconnect->setEnabled(ui->btnDisconnect->isEnabled());
    if(ui->groupConnection->property("rc13Collapsed").toBool()){
        const QString compactText=QStringLiteral("%1  %2:%3 | %4 | %5")
            .arg(m_controlLoggedIn?QStringLiteral("已连接"):QStringLiteral("未连接"),ui->editHost->text().trimmed())
            .arg(ui->spinPort->value()).arg(ui->comboRouterConnectionMode->currentText(),ui->editUser->text());
        if(auto* compact=ui->groupConnection->findChild<QLabel*>(QStringLiteral("labelConnectionCompact")))compact->setText(compactText);
    }
    ui->btnOneClickDiagnosis->setEnabled(controlReady&&captureReady&&!workflow);
    ui->btnCancelOneClick->setEnabled(workflow);
    if(m_globalStopDiagnosisButton)m_globalStopDiagnosisButton->setVisible(workflow);
    ui->btnDiagnose->setEnabled(controlReady&&!workflow);
    ui->btnPingMaster->setEnabled(controlReady&&!workflow);
    ui->btnPingTerminal->setEnabled(controlReady&&ethernet&&!workflow);
    const bool terminalCaptureAllowed=!(ui->comboCaptureMode->currentIndex()==2 && !ethernet);
    ui->btnStartCapture->setEnabled(captureReady&&!workflow&&terminalCaptureAllowed&&!(m_capCtrl&&m_capCtrl->isRunning()));
    ui->btnStopCapture->setEnabled(m_capCtrl&&m_capCtrl->isRunning());
    updateFieldSummary();
}

void MainWindow::loadFieldHistory(){
    QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
    const QStringList masters=settings.value(QStringLiteral("field/masterHistory")).toStringList();
    const QStringList terminals=settings.value(QStringLiteral("field/terminalHistory")).toStringList();
    ui->editMasterIp->setCompleter(new QCompleter(masters,ui->editMasterIp));
    ui->editTerminalIp->setCompleter(new QCompleter(terminals,ui->editTerminalIp));
    const QString lastMaster=settings.value(QStringLiteral("field/lastMaster")).toString();
    const QString lastTerminal=settings.value(QStringLiteral("field/lastTerminal")).toString();
    const int lastTerminalPort=settings.value(QStringLiteral("field/lastTerminalPort"),2404).toInt();
    const int masterRole=settings.value(QStringLiteral("field/masterRole"),0).toInt();
    const int terminalRole=settings.value(QStringLiteral("field/terminalRole"),1).toInt();
    const int expectedSeconds=settings.value(QStringLiteral("field/expectedConnectionSeconds"),60).toInt();
    if(ui->editMasterIp->text().isEmpty()&&!lastMaster.isEmpty())ui->editMasterIp->setText(lastMaster);
    if(ui->editTerminalIp->text().isEmpty()&&!lastTerminal.isEmpty())ui->editTerminalIp->setText(lastTerminal);
    if(lastTerminalPort>0&&lastTerminalPort<=65535)ui->spinTerminalPort->setValue(lastTerminalPort);
    ui->comboMasterRole->setCurrentIndex(masterRole==1?1:0);
    ui->comboTerminalRole->setCurrentIndex(terminalRole==0?0:1);
    ui->spinExpectedConnectionSeconds->setValue(qBound(10,expectedSeconds,600));
}

void MainWindow::saveFieldHistory(){
    QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
    auto save=[&settings](const QString& key,const QString& value){
        if(value.isEmpty())return;
        QStringList history=settings.value(key).toStringList();history.removeAll(value);history.prepend(value);
        while(history.size()>20)history.removeLast();settings.setValue(key,history);
    };
    const QString master=ui->editMasterIp->text().trimmed();
    const QString terminal=ui->editTerminalIp->text().trimmed();
    if(ConnectivityProbe::isValidIpv4(master)){save(QStringLiteral("field/masterHistory"),master);settings.setValue(QStringLiteral("field/lastMaster"),master);}
    if(ConnectivityProbe::isValidIpv4(terminal)){save(QStringLiteral("field/terminalHistory"),terminal);settings.setValue(QStringLiteral("field/lastTerminal"),terminal);}
    settings.setValue(QStringLiteral("field/lastTerminalPort"),ui->spinTerminalPort->value());
    settings.setValue(QStringLiteral("field/masterRole"),ui->comboMasterRole->currentIndex());
    settings.setValue(QStringLiteral("field/terminalRole"),ui->comboTerminalRole->currentIndex());
    settings.setValue(QStringLiteral("field/expectedConnectionSeconds"),ui->spinExpectedConnectionSeconds->value());
}

void MainWindow::updateTerminalTransportUi(){
    const bool ethernet=ui->comboTerminalTransport->currentIndex()==0;
    ui->labelTerminalIp->setVisible(ethernet);
    ui->editTerminalIp->setVisible(ethernet);
    ui->labelTerminalPort->setVisible(ethernet);
    ui->spinTerminalPort->setVisible(ethernet);
    ui->labelTerminalRole->setVisible(ethernet);
    ui->comboTerminalRole->setVisible(ethernet);
    ui->btnPingTerminal->setVisible(ethernet);
    ui->editTerminalIp->setEnabled(ethernet);
    ui->spinTerminalPort->setEnabled(ethernet);
    if(ethernet){
        ui->editTerminalIp->setToolTip(QStringLiteral("网口模式：从路由器Ping终端IP；终端抓包会按终端IP网段自动选择 br0 或 br0:1"));
        ui->spinTerminalPort->setToolTip(QStringLiteral("终端业务TCP端口，例如2404、9999或5051"));
        ui->labelTerminalModeHint->setText(QStringLiteral("网口：Ping + LAN TCP抓包（按终端IP自动匹配 br0/br0:1）；角色决定谁应主动发起连接。"));
        ui->labelTerminalModeHint->show();
    }else{
        const QString tip=QStringLiteral("串口模式依据DTS/systemlog中的串口配置和收发证据判断；/dev/ttyUSB*属于模组控制口证据，不作为终端串口。");
        ui->editTerminalIp->setToolTip(tip);
        ui->spinTerminalPort->setToolTip(tip);
        ui->labelTerminalModeHint->clear();
        ui->labelTerminalModeHint->hide();
    }
    if(m_serialCommunicationTab>=0)ui->packetDetailTabs->setTabVisible(m_serialCommunicationTab,!ethernet);
    if(m_serialTimelineTab>=0)ui->packetDetailTabs->setTabVisible(m_serialTimelineTab,!ethernet);
    if(ethernet && ui->comboCaptureMode->currentIndex()==2)setCaptureInterfaceText(autoTerminalCaptureInterface());
    if(!ethernet && m_serialCommunicationLog && m_serialCommunicationLog->document()->isEmpty()){
        m_serialCommunicationLog->setPlainText(routerSerialMode()?QStringLiteral("等待串口控制台日志...\n说明：这里与网络抓包分开显示。"):QStringLiteral("终端已选择串口通讯。当前路由器连接不是PC串口控制台，因此没有可直接显示的串口控制台数据；网络侧仍可在实时抓包中选择WAN/主站/自定义接口抓包。"));
    }
    if(ui->comboCaptureMode->currentIndex()==2)updateCaptureModeUi();
    updateConnectionUi();
    renderFieldDiagnosis();
}

void MainWindow::pingMaster(){
    if(m_workflow&&m_workflow->isRunning()){log(QStringLiteral("一键现场诊断正在运行"));return;}
    saveFieldHistory();
    if(controlCommandBusy()){log(QStringLiteral("控制通道正在执行其他命令，请等待完成后再Ping主站"));return;}
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    if(!ConnectivityProbe::isValidIpv4(cfg.masterIp)){
        log(QStringLiteral("主站IP无效，请填写IPv4地址"));
        return;
    }
    m_masterPingAttempted=true;
    m_masterPing=PingResult{};
    m_fieldPingMode=FieldPingMode::Master;
    m_fieldDiag->setConfig(cfg);
    m_fieldDiag->pingMaster();
    renderFieldDiagnosis();
}

void MainWindow::pingTerminal(){
    if(m_workflow&&m_workflow->isRunning()){log(QStringLiteral("一键现场诊断正在运行"));return;}
    saveFieldHistory();
    if(controlCommandBusy()){log(QStringLiteral("控制通道正在执行其他命令，请等待完成后再Ping终端"));return;}
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    if(cfg.terminalTransport!=TerminalTransport::Ethernet){
        log(QStringLiteral("串口模式不执行终端IP Ping；依据DTS/systemlog证据分析"));
        return;
    }
    if(!ConnectivityProbe::isValidIpv4(cfg.terminalIp)){
        log(QStringLiteral("终端IP无效，请填写IPv4地址"));
        return;
    }
    QString subnetError;
    if(!validateTerminalLanSubnet(cfg.terminalIp,&subnetError)){
        log(subnetError);
        statusBar()->showMessage(subnetError,10000);
        return;
    }
    m_terminalPingAttempted=true;
    m_terminalPing=PingResult{};
    m_fieldPingMode=FieldPingMode::TerminalEthernet;
    m_fieldDiag->setConfig(cfg);
    m_fieldDiag->pingTerminal();
    renderFieldDiagnosis();
}

bool MainWindow::startFieldCapture(FieldCaptureMode mode,const QString& iface,const QString& filter,const ChannelCriteria& criteria,bool promptForStorage){
    if(!captureTransportReady()){
        log(QStringLiteral("抓包控制通道未建立，请先连接路由器"));
        return false;
    }
    if(m_capCtrl->isRunning()){
        log(QStringLiteral("已有抓包正在运行，请先停止当前抓包"));
        return false;
    }
    if(iface.trimmed().isEmpty() || filter.trimmed().isEmpty()){
        log(QStringLiteral("自动抓包参数不完整"));
        return false;
    }
    m_offline->stopReplay();
    clearPacketView();
    const QString prefix=mode==FieldCaptureMode::Master ? QStringLiteral("master") : QStringLiteral("terminal_lan");
    if(promptForStorage){if(!prepareCaptureStorage(prefix))return false;}
    else m_capCtrl->clearDirectSave();
    m_fieldCaptureMode=mode;
    m_fieldChannelAnalyzer=std::make_unique<ChannelAnalyzer>(criteria);
    if(mode==FieldCaptureMode::Master){
        m_masterChannelEvidence=ChannelEvidence{};
        m_actualMasterIps.clear();m_actualMasterSessions.clear();m_masterDownstreamPayloads.clear();m_masterUpstreamPayloadPackets=0;
    }
    if(mode==FieldCaptureMode::TerminalEthernet) m_terminalChannelEvidence=ChannelEvidence{};
    m_activeCaptureIface=iface;
    m_activeCaptureFilter=filter;
    log(QStringLiteral("自动抓包: tcpdump -i %1 ... %2").arg(iface,filter));
    m_capCtrl->start(iface,filter);
    renderFieldDiagnosis();
    return m_capCtrl->isRunning();
}

void MainWindow::captureMaster(){
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    const QString filter=FieldDiagnosticController::buildMasterFilter(cfg);
    if(filter.isEmpty()){
        log(QStringLiteral("主站IP或业务端口无效"));
        return;
    }
    const QString iface=captureInterfaceText();
    if(iface.isEmpty()){
        log(QStringLiteral("WAN接口为空，请先执行WAN诊断或手工填写 usb0/ppp0 等实际接口"));
        return;
    }
    ChannelCriteria criteria;
    criteria.peerIp.clear(); // configured master IP is only a reference; real client IP may differ
    criteria.peerPort=cfg.masterPort;
    criteria.requirePeerPort=true;
    startFieldCapture(FieldCaptureMode::Master,iface,filter,criteria);
}

void MainWindow::captureTerminal(){
    const FieldDiagnosticConfig cfg=currentFieldConfig();
    if(cfg.terminalTransport!=TerminalTransport::Ethernet){
        log(QStringLiteral("串口模式不执行终端LAN抓包；依据DTS/systemlog证据分析"));
        return;
    }
    const QString filter=FieldDiagnosticController::buildTerminalFilter(cfg);
    if(filter.isEmpty()){
        log(QStringLiteral("终端IP或终端端口无效"));
        return;
    }
    QString subnetError;
    if(!validateTerminalLanSubnet(cfg.terminalIp,&subnetError)){
        log(subnetError);
        statusBar()->showMessage(subnetError,10000);
        return;
    }
    ChannelCriteria criteria;
    criteria.peerIp=cfg.terminalIp;
    criteria.peerPort=cfg.terminalPort;
    criteria.requirePeerPort=true;
    startFieldCapture(FieldCaptureMode::TerminalEthernet,autoTerminalCaptureInterface(),filter,criteria);
}

LayerDiagnosis MainWindow::currentTransportLayer() const{
    const FieldDiagnosticConfig cfg=currentFieldConfig();

    bool masterBlockedByWan=false;
    QString wanPrerequisiteEvidence;
    if(!m_lastDiagnosis.type.isEmpty()){
        const QList<LayerDiagnosis> wanLayers=DiagnosisEngine::diagnoseWanLayers(m_lastStatus);
        if(wanLayers.size()>=4 && (wanLayers.at(3).state==LayerState::Error || wanLayers.at(3).state==LayerState::NotTested)){
            masterBlockedByWan=true;
            wanPrerequisiteEvidence=wanLayers.at(3).conclusion;
        }
    }

    LayerDiagnosis master;
    master.layer=QStringLiteral("MASTER_CHANNEL");
    if(!ConnectivityProbe::isValidIpv4(cfg.masterIp)){
        master.state=LayerState::NotTested;
        master.confidence=Confidence::Low;
        master.conclusion=QStringLiteral("主站IP未配置，主站链路未测试");
    }else if(m_masterChannelEvidence.packets>0 || (m_masterPingAttempted&&m_masterPing.reachable)){
        master=ChannelAnalyzer::diagnoseMaster(m_masterPing,m_masterChannelEvidence,cfg.masterRole,cfg.expectedConnectionSeconds);
    }else if(masterBlockedByWan){
        master.state=LayerState::NotTested;
        master.confidence=Confidence::High;
        master.conclusion=QStringLiteral("WAN尚未具备有效测试条件，主站TCP链路暂不做失败判定");
        if(!wanPrerequisiteEvidence.isEmpty())master.evidence<<QStringLiteral("上游WAN：%1").arg(wanPrerequisiteEvidence);
        if(m_masterPingAttempted&&!m_masterPing.evidence.isEmpty())
            for(const QString& e:m_masterPing.evidence)master.evidence<<QStringLiteral("Ping辅助证据：%1").arg(e);
        master.suggestions<<QStringLiteral("先恢复蜂窝注册/WAN地址，再验证主站 %1:%2").arg(cfg.masterIp).arg(cfg.masterPort);
    }else if(m_masterPingAttempted){
        master=ChannelAnalyzer::diagnoseMaster(m_masterPing,m_masterChannelEvidence,cfg.masterRole,cfg.expectedConnectionSeconds);
    }else{
        master.state=LayerState::NotTested;
        master.confidence=Confidence::Low;
        master.conclusion=QStringLiteral("主站链路未测试；将分析 %1:%2 的Ping及TCP会话").arg(cfg.masterIp).arg(cfg.masterPort);
    }

    const QStringList actualMasterIps=ChannelAnalyzer::actualPeerIps(m_masterChannelEvidence,cfg.masterRole,cfg.masterPort);
    if(!actualMasterIps.isEmpty()){
        master.evidence<<QStringLiteral("配置主站IP：%1").arg(cfg.masterIp);
        master.evidence<<QStringLiteral("实际主站连接IP：%1").arg(actualMasterIps.join(QStringLiteral(", ")));
        if(!actualMasterIps.contains(cfg.masterIp)){
            master.evidence<<QStringLiteral("实际主站连接源IP与配置主站IP不一致；可能存在NAT、出口地址转换、集群或备用主站。该差异仅提示，不直接判故障");
            master.suggestions<<QStringLiteral("如需核对来源，请在主站侧确认NAT/集群/备用出口；后续诊断以实际TCP五元组为准");
        }
    }

    LayerDiagnosis terminal;
    if(cfg.terminalTransport==TerminalTransport::Serial){
        terminal.layer=QStringLiteral("TERMINAL_SERIAL");
        if(!m_masterDownstreamPayloads.isEmpty() && m_masterUpstreamPayloadPackets==0){
            terminal.state=LayerState::Warning;
            terminal.confidence=Confidence::High;
            terminal.conclusion=QStringLiteral("主站已有业务数据到达WAN，但诊断窗口内未观察到WAN返回主站的业务Payload；请检查串口终端配置、接线及终端应答");
            terminal.evidence<<QStringLiteral("主站→WAN业务报文：%1条；WAN→主站业务响应：0条").arg(m_masterDownstreamPayloads.size());
            const int maxPrint=qMin(10,m_masterDownstreamPayloads.size());
            for(int idx=0;idx<maxPrint;++idx){
                const ParsedPacket& packet=m_masterDownstreamPayloads.at(idx);
                const QByteArray preview=packet.payload.left(128);
                QString ascii;
                for(char ch:preview){const uchar c=static_cast<uchar>(ch);ascii+=(c>=32&&c<=126)?QChar(c):QLatin1Char('.');}
                terminal.evidence<<QStringLiteral("主站下发数据%1：%2 | %3:%4 → %5:%6 | %7 bytes | HEX=%8 | ASCII=%9")
                    .arg(idx+1)
                    .arg(packet.timestamp.toLocalTime().toString(QStringLiteral("HH:mm:ss.zzz")))
                    .arg(packet.sourceIp).arg(packet.sourcePort).arg(packet.destinationIp).arg(packet.destinationPort)
                    .arg(packet.payload.size())
                    .arg(QString::fromLatin1(preview.toHex(' ')).toUpper(),ascii);
                const ProtocolEvidence proto=ProtocolDiagnosis::analyzeTcpPayload(packet.payload);
                for(const QString& ev:proto.evidence)terminal.evidence<<QStringLiteral("主站下发数据%1 协议解析：%2").arg(idx+1).arg(ev);
            }
            if(m_masterDownstreamPayloads.size()>maxPrint)
                terminal.evidence<<QStringLiteral("另有%1条主站下发业务报文未在摘要中展开，可在实时抓包窗口查看完整Payload/HEX").arg(m_masterDownstreamPayloads.size()-maxPrint);
            terminal.suggestions<<QStringLiteral("检查串口终端配置、TX/RX/GND接线、波特率/数据位/停止位/校验位、串口映射、终端站号与协议配置")
                                <<QStringLiteral("确认终端收到主站下发数据后是否有串口应答；如有串口应答但WAN仍无回包，再检查串口转TCP映射和上行发送逻辑");
        }else if(m_lastStatus.southTcpConnected){
            terminal.state=LayerState::Warning;
            terminal.confidence=Confidence::High;
            terminal.conclusion=QStringLiteral("界面选择串口，但当前日志实际观察到终端南向通道为TCP；不能据此认定终端正在走串口");
            if(!m_lastStatus.dcuIp.isEmpty())
                terminal.evidence<<QStringLiteral("south TCP client: %1:%2").arg(m_lastStatus.dcuIp).arg(m_lastStatus.dcuPort);
            if(m_lastStatus.serialBaudrate>0)
                terminal.evidence<<QStringLiteral("同时存在serial1配置: %1 bps").arg(m_lastStatus.serialBaudrate);
            terminal.suggestions<<QStringLiteral("结合DTS收发日志确认现场实际南向通讯方式");
        }else if(m_lastStatus.serialBaudrate>0){
            terminal.state=LayerState::Unknown;
            terminal.confidence=Confidence::Medium;
            terminal.conclusion=QStringLiteral("已读取终端串口配置，但当前证据不足以确认实际串口收发是否正常");
            terminal.evidence<<QStringLiteral("serial1: %1 bps, data=%2, stop=%3, parity=%4, flow=%5")
                                  .arg(m_lastStatus.serialBaudrate).arg(m_lastStatus.serialDatabit)
                                  .arg(m_lastStatus.serialStopbit).arg(m_lastStatus.serialParity)
                                  .arg(m_lastStatus.serialFlowcontrol);
            terminal.suggestions<<QStringLiteral("导入包含DTS终端收发方向和原始数据的systemlog进一步判断");
        }else{
            terminal.state=LayerState::NotTested;
            terminal.confidence=Confidence::Low;
            terminal.conclusion=QStringLiteral("串口模式不执行IP Ping或br0抓包；尚无DTS串口收发证据");
        }
        terminal.evidence<<QStringLiteral("/dev/ttyUSB*仅作为模组AT控制口证据，不作为终端串口");
    }else{
        terminal.layer=QStringLiteral("TERMINAL_ETHERNET");
        if(!ConnectivityProbe::isValidIpv4(cfg.terminalIp)){
            terminal.state=LayerState::NotTested;
            terminal.confidence=Confidence::Low;
            terminal.conclusion=QStringLiteral("终端网口模式未配置有效终端IP或端口");
        }else if(m_terminalPingAttempted || m_terminalChannelEvidence.packets>0){
            terminal=ChannelAnalyzer::diagnoseTerminalEthernet(m_terminalPing,m_terminalChannelEvidence,cfg.terminalRole,cfg.expectedConnectionSeconds);
        }else{
            terminal.state=LayerState::NotTested;
            terminal.confidence=Confidence::Low;
            terminal.conclusion=QStringLiteral("终端网口尚未测试；将分析 %1:%2 的Ping及TCP会话").arg(cfg.terminalIp).arg(cfg.terminalPort);
        }
    }

    LayerDiagnosis transport;
    transport.layer=QStringLiteral("TRANSPORT");
    transport.confidence=Confidence::Low;
    transport.state=LayerState::NotTested;
    transport.conclusion=QStringLiteral("主站与终端链路尚未测试");

    const QList<QPair<QString,LayerDiagnosis>> children{
        {QStringLiteral("主站链路"),master},
        {cfg.terminalTransport==TerminalTransport::Ethernet?QStringLiteral("终端网口链路"):QStringLiteral("终端串口链路"),terminal}
    };
    int bestRank=-1;
    const LayerDiagnosis* selected=nullptr;
    bool anyObserved=false;
    for(const auto& named:children){
        const QString& label=named.first;
        const LayerDiagnosis& child=named.second;
        transport.evidence<<QStringLiteral("%1：%2").arg(label,child.conclusion);
        for(const QString& e:child.evidence)transport.evidence<<QStringLiteral("%1 - %2").arg(label,e);
        appendUnique(transport.suggestions,child.suggestions);
        if(child.state!=LayerState::NotTested)anyObserved=true;
        const int rank=layerRank(child.state);
        if(child.state!=LayerState::NotTested && rank>bestRank){bestRank=rank;selected=&child;}
    }
    if(anyObserved && selected){
        transport.state=selected->state;
        transport.confidence=selected->confidence;
        if(transport.state==LayerState::Error)
            transport.conclusion=QStringLiteral("主站与终端链路存在明确异常：%1").arg(selected->conclusion);
        else if(transport.state==LayerState::Warning)
            transport.conclusion=QStringLiteral("主站与终端链路存在需要关注的现象：%1").arg(selected->conclusion);
        else if(transport.state==LayerState::Normal)
            transport.conclusion=QStringLiteral("当前已测试的主站与终端链路未发现明确异常");
        else
            transport.conclusion=QStringLiteral("已获得部分主站与终端链路证据，但仍不足以给出明确正常/异常结论");
    }
    if(!m_syncCaptureSharedInterface){
        const DualCaptureCorrelationSummary correlation=m_dualCaptureCorrelator.summary();
        for(const QString& e:correlation.evidence)transport.evidence<<QStringLiteral("双点抓包 - %1").arg(e);
        if(!m_syncWorkflowCaptureActive && correlation.matchedPackets==0 && (correlation.terminalOnlyPackets>0||correlation.wanOnlyPackets>0)){
            if(transport.state==LayerState::Normal){transport.state=LayerState::Warning;transport.confidence=Confidence::Medium;}
            transport.suggestions<<QStringLiteral("双点抓包存在未关联Payload；结合方向判断路由/NAT/转发链路中哪一侧未继续转发");
        }
    }
    return transport;
}

FieldDiagnosisReport MainWindow::currentFieldReport() const{
    FieldDiagnosisReport field;
    if(!m_lastDiagnosis.type.isEmpty()){
        field.layers=DiagnosisEngine::diagnoseWanLayers(m_lastStatus);
    }else{
        const QList<QPair<QString,QString>> missing={
            {QStringLiteral("CELLULAR_MODULE"),QStringLiteral("模组/AT尚未测试")},
            {QStringLiteral("SIM"),QStringLiteral("SIM卡尚未测试")},
            {QStringLiteral("REGISTRATION"),QStringLiteral("蜂窝网络注册尚未测试")},
            {QStringLiteral("WAN"),QStringLiteral("WAN/IP尚未测试")}
        };
        for(const auto& item:missing){
            LayerDiagnosis d;d.layer=item.first;d.state=LayerState::NotTested;d.confidence=Confidence::Low;d.conclusion=item.second;
            field.layers<<d;
        }
    }
    field.layers<<currentTransportLayer();

    QList<LayerDiagnosis> all=field.layers;
    ProtocolEvidence protocol=m_protocolEvidence;
    protocol.layers=ProtocolDiagnosis::buildLayers(protocol);
    all.append(protocol.layers);
    const LayerDiagnosis* worst=nullptr;
    for(const LayerDiagnosis& d:all){
        if(d.state==LayerState::NotTested)continue;
        if(!worst || layerRank(d.state)>layerRank(worst->state))worst=&d;
    }
    int normalCount=0,notTestedCount=0,unknownCount=0;
    for(const LayerDiagnosis& d:all){
        if(d.state==LayerState::Normal)++normalCount;
        else if(d.state==LayerState::NotTested)++notTestedCount;
        else if(d.state==LayerState::Unknown)++unknownCount;
    }
    if(!worst)
        field.overallConclusion=QStringLiteral("尚未形成足够诊断证据，请按现场流程从蜂窝/WAN、TCP链路到业务数据逐层测试");
    else if(worst->state==LayerState::Error)
        field.overallConclusion=QStringLiteral("故障主要定位在【%1】：%2").arg(layerTitle(worst->layer),worst->conclusion);
    else if(worst->state==LayerState::Warning)
        field.overallConclusion=QStringLiteral("当前存在需要重点关注的现象【%1】：%2").arg(layerTitle(worst->layer),worst->conclusion);
    else if(normalCount>=6 && notTestedCount==0 && unknownCount==0)
        field.overallConclusion=QStringLiteral("模组、SIM、网络注册、WAN、主站/终端链路及业务数据均有正常证据，当前未发现明显通信故障");
    else if(worst->state==LayerState::Normal)
        field.overallConclusion=QStringLiteral("当前已测试层未发现明确异常；仍有未测试或证据不足的层级需要补充验证");
    else
        field.overallConclusion=QStringLiteral("已有部分诊断证据，但仍不足以定位最终故障层");

    // TCP会话结果不能只藏在“TCP会话/证据”详情里。只要已经形成实际TCP判断，
    // 就把主站/终端的结果同时写进综合结论；未测试/被WAN前置条件阻断的项目不追加。
    if(!field.layers.isEmpty()){
        const LayerDiagnosis& transport=field.layers.constLast();
        const QStringList tcpResults=tcpOutcomeSummaries(transport);
        if(!tcpResults.isEmpty()){
            const QString tcpText=QStringLiteral("TCP结果：%1").arg(tcpResults.join(QStringLiteral("；")));
            if(!field.overallConclusion.contains(tcpText))field.overallConclusion+=QStringLiteral("；")+tcpText;
        }
    }
    return field;
}

QString MainWindow::currentLayeredReport() const{
    ProtocolEvidence protocol=m_protocolEvidence;
    protocol.layers=ProtocolDiagnosis::buildLayers(protocol);
    return ReportExporter::buildFieldReport(m_lastStatus,currentFieldReport(),protocol);
}

void MainWindow::consumeProtocolPayload(const QByteArray& payload){
    const ProtocolEvidence part=ProtocolDiagnosis::analyzeTcpPayload(payload);
    if(part.gridFrames==0 && part.iec101Frames==0 && part.iec104Frames==0)return;
    ProtocolDiagnosis::merge(m_protocolEvidence,part);
    renderFieldDiagnosis();
}

void MainWindow::rebuildProtocolEvidenceFromStreams(){
    ProtocolEvidence rebuilt;
    for(const ReassembledTcpDirection& direction:m_tcpReassembler.directions()){
        if(direction.bytes.isEmpty())continue;
        const ProtocolEvidence part=ProtocolDiagnosis::analyzeTcpPayload(direction.bytes);
        if(part.gridFrames==0 && part.iec101Frames==0 && part.iec104Frames==0)continue;
        ProtocolDiagnosis::merge(rebuilt,part);
        if(direction.gapObserved)
            rebuilt.evidence<<QStringLiteral("TCP流 %1 → %2 曾观察到分段缺口；只分析已连续重组的字节，不补造缺失数据")
                .arg(direction.sourceEndpoint,direction.destinationEndpoint);
    }
    const Iec104SessionSummary iec104=Iec104SessionAnalyzer::analyze(m_tcpReassembler.directions());
    if(iec104.validFrames>0){
        rebuilt.iec104StartDtActSeen=rebuilt.iec104StartDtActSeen||iec104.startDtActSeen;
        rebuilt.iec104StartDtConSeen=rebuilt.iec104StartDtConSeen||iec104.startDtConSeen;
        rebuilt.iec104StopDtActSeen=rebuilt.iec104StopDtActSeen||iec104.stopDtActSeen;
        rebuilt.iec104StopDtConSeen=rebuilt.iec104StopDtConSeen||iec104.stopDtConSeen;
        rebuilt.iec104TestFrActSeen=rebuilt.iec104TestFrActSeen||iec104.testFrActSeen;
        rebuilt.iec104TestFrConSeen=rebuilt.iec104TestFrConSeen||iec104.testFrConSeen;
        rebuilt.iec104SequenceGaps=iec104.sequenceGapCount;
        rebuilt.iec104DuplicateIFrames=iec104.duplicateIFrameCount;
        rebuilt.iec104OutstandingIFrames=iec104.outstandingIFrames;
        appendUnique(rebuilt.evidence,iec104.evidence);
    }
    rebuilt.layers=ProtocolDiagnosis::buildLayers(rebuilt);
    m_protocolEvidence=rebuilt;
    renderFieldDiagnosis();
}

QList<LayerDiagnosis> MainWindow::currentSixLayers() const{
    const FieldDiagnosisReport field=currentFieldReport();
    ProtocolEvidence protocol=m_protocolEvidence;
    protocol.layers=ProtocolDiagnosis::buildLayers(protocol);
    QList<LayerDiagnosis> source=field.layers;source.append(protocol.layers);
    const QStringList order={QStringLiteral("CELLULAR_MODULE"),QStringLiteral("SIM"),QStringLiteral("REGISTRATION"),
                             QStringLiteral("WAN"),QStringLiteral("TRANSPORT"),QStringLiteral("BUSINESS_DATA")};
    QList<LayerDiagnosis> result;
    for(const QString& name:order){
        bool found=false;
        for(const LayerDiagnosis& d:source){if(d.layer==name){result<<d;found=true;break;}}
        if(!found){LayerDiagnosis d;d.layer=name;d.state=LayerState::NotTested;d.confidence=Confidence::Low;d.conclusion=QStringLiteral("尚未测试");result<<d;}
    }
    return result;
}

QList<LayerDiagnosis> MainWindow::currentPresentationLayers() const
{
    const QList<LayerDiagnosis> internal=currentSixLayers();
    if(internal.size()<6)return internal;
    LayerDiagnosis access;
    access.layer=QStringLiteral("ACCESS");
    access.state=LayerState::NotTested;
    access.confidence=Confidence::Low;
    int worst=-1;
    const QStringList labels={QStringLiteral("模组"),QStringLiteral("SIM"),QStringLiteral("网络注册")};
    QStringList conclusions;
    for(int k=0;k<3;++k){
        const LayerDiagnosis& child=internal.at(k);
        conclusions<<QStringLiteral("%1：%2").arg(labels.at(k),child.conclusion);
        const int rank=layerRank(child.state);
        if(rank>worst){worst=rank;access.state=child.state;access.confidence=child.confidence;}
        access.evidence<<QStringLiteral("【%1】状态=%2，置信度=%3").arg(labels.at(k),layerStateText(child.state),confidenceText(child.confidence));
        for(const QString& ev:child.evidence)access.evidence<<QStringLiteral("%1 - %2").arg(labels.at(k),ev);
        for(const QString& tip:child.suggestions)access.suggestions<<QStringLiteral("%1 - %2").arg(labels.at(k),tip);
    }
    access.conclusion=conclusions.join(QStringLiteral("；"));
    QList<LayerDiagnosis> result;
    result<<access<<internal.at(3)<<internal.at(4)<<internal.at(5);
    return result;
}


QString MainWindow::layerDetailText(const LayerDiagnosis& d) const{
    QString text=QStringLiteral("%1\n状态：%2\n置信度：%3\n\n结论：\n%4\n")
        .arg(layerTitle(d.layer),layerStateText(d.state),confidenceText(d.confidence),d.conclusion);
    if(!d.evidence.isEmpty()){
        text+=QStringLiteral("\n证据：\n");
        for(const QString& e:d.evidence)text+=QStringLiteral("- %1\n").arg(e);
    }
    if(!d.suggestions.isEmpty()){
        text+=QStringLiteral("\n建议：\n");
        for(const QString& tip:d.suggestions)text+=QStringLiteral("- %1\n").arg(tip);
    }
    return text;
}

void MainWindow::showLayerDetail(int row){
    const QList<LayerDiagnosis> layers=currentPresentationLayers();
    if(row<0||row>=layers.size()){
        ui->txtLayerDetail->clear();
        if(m_fieldEvidenceTree)m_fieldEvidenceTree->clear();
        return;
    }
    const LayerDiagnosis layer=layers.at(row);
    ui->txtLayerDetail->setPlainText(layerDetailText(layer));
    populateEvidenceTree(layer);
}

QString MainWindow::packetDetailText(const ParsedPacket& p) const{
    QString text;
    text+=QStringLiteral("时间：%1\n").arg(p.timestamp.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
    text+=QStringLiteral("方向：%1:%2 → %3:%4\n").arg(p.sourceIp).arg(p.sourcePort).arg(p.destinationIp).arg(p.destinationPort);
    text+=QStringLiteral("协议：%1\n捕获长度：%2\nIPv4总长度：%3\n").arg(p.protocol).arg(p.capturedLength).arg(p.ipTotalLength);
    if(p.protocol==QStringLiteral("TCP")){
        text+=QStringLiteral("TCP flags：0x%1  SEQ=%2  ACK=%3  Payload=%4 bytes\n")
            .arg(QString::number(p.tcpFlags,16).rightJustified(2,QLatin1Char('0'))).arg(p.sequence).arg(p.acknowledgement).arg(p.tcpPayloadLength);
    }
    if(p.protocol==QStringLiteral("ICMP"))text+=QStringLiteral("ICMP type：%1\n").arg(p.icmpType);
    text+=QStringLiteral("摘要：%1\n").arg(p.summary);
    if(!p.payload.isEmpty()){
        const QByteArray preview=p.payload.left(160);
        text+=QStringLiteral("\nPayload HEX%1：\n%2\n")
            .arg(p.payload.size()>preview.size()?QStringLiteral("（前160字节）"):QString())
            .arg(QString::fromLatin1(preview.toHex(' ')).toUpper());
        const ProtocolEvidence e=ProtocolDiagnosis::analyzeTcpPayload(p.payload);
        if(e.gridFrames||e.iec101Frames||e.iec104Frames){
            text+=QStringLiteral("\n协议识别：\n");
            for(const QString& ev:e.evidence)text+=QStringLiteral("- %1\n").arg(ev);
            for(const LayerDiagnosis& layer:e.layers)text+=QStringLiteral("- %1：%2\n").arg(layerTitle(layer.layer),layer.conclusion);
        }
    }
    return text;
}

QString MainWindow::packetHexText(const ParsedPacket& p) const{
    if(p.payload.isEmpty())return QStringLiteral("当前数据包没有 TCP Payload。\n\n协议：%1\n摘要：%2").arg(p.protocol,p.summary);
    QString out=QStringLiteral("Payload：%1 bytes\n\n").arg(p.payload.size());
    const QByteArray data=p.payload;
    for(int offset=0;offset<data.size();offset+=16){
        const QByteArray chunk=data.mid(offset,16);
        QString hex;
        QString ascii;
        for(int i=0;i<16;++i){
            if(i<chunk.size()){
                const unsigned char c=static_cast<unsigned char>(chunk.at(i));
                hex+=QStringLiteral("%1 ").arg(c,2,16,QLatin1Char('0')).toUpper();
                ascii+=(c>=32&&c<=126)?QChar(c):QLatin1Char('.');
            }else{
                hex+=QStringLiteral("   ");
            }
        }
        out+=QStringLiteral("%1  %2 |%3|\n").arg(offset,4,16,QLatin1Char('0')).arg(hex,ascii);
    }
    return out;
}

QString MainWindow::packetBusinessText(const ParsedPacket& p) const{
    if(p.protocol!=QStringLiteral("TCP"))return QStringLiteral("当前包不是 TCP，暂不进行 IEC101/IEC104/国网加密业务识别。");
    if(p.payload.isEmpty())return QStringLiteral("当前 TCP 包没有 Payload；纯 ACK、握手或关闭报文出现这种情况是正常的。");
    QByteArray businessBytes=m_tcpReassembler.bytesForPacketDirection(p);
    if(businessBytes.isEmpty())businessBytes=p.payload;
    const ProtocolEvidence e=ProtocolDiagnosis::analyzeTcpPayload(businessBytes);
    QString out=QStringLiteral("当前包 TCP Payload：%1 bytes\n重组后本方向连续 TCP 字节流：%2 bytes\n").arg(p.payload.size()).arg(businessBytes.size());
    if(e.gridFrames==0&&e.iec101Frames==0&&e.iec104Frames==0){
        out+=QStringLiteral("识别结果：当前 Payload 未识别为可确认的 IEC101、IEC104 或国网加密外层业务帧。\n");
        out+=QStringLiteral("说明：这不等于业务异常，也可能是其它协议、尚未形成完整连续业务帧或加密内容；程序优先按TCP序号重组后再识别。\n");
        return out;
    }
    out+=QStringLiteral("识别统计：IEC101=%1  IEC104=%2  国网加密外层=%3\n\n")
        .arg(e.iec101Frames).arg(e.iec104Frames).arg(e.gridFrames);
    if(!e.evidence.isEmpty()){
        out+=QStringLiteral("证据：\n");
        for(const QString& value:e.evidence)out+=QStringLiteral("- %1\n").arg(value);
    }
    if(!e.layers.isEmpty()){
        out+=QStringLiteral("\n结论：\n");
        for(const LayerDiagnosis& d:e.layers){
            if(d.layer==QStringLiteral("BUSINESS_DATA") || d.layer==QStringLiteral("GRID_SECURITY") || d.layer==QStringLiteral("IEC101") || d.layer==QStringLiteral("IEC104"))
                out+=QStringLiteral("- %1：%2\n").arg(layerTitle(d.layer),d.conclusion);
        }
    }
    if(e.gridFrames>0 && e.iec101Frames==0 && e.iec104Frames==0)
        out+=QStringLiteral("\n提示：已识别加密/安全外层业务；没有明文证据时不会推断内部一定是 IEC101 或 IEC104。\n");
    return out;
}

void MainWindow::refreshRealtimeTcpAnalysis(){
    if(!ui->txtRealtimeTcpSessions)return;
    ui->txtRealtimeTcpSessions->setPlainText(ChannelAnalyzer::tcpSessionReport(m_packetChannelAnalyzer.evidence(),QStringLiteral("实时 TCP 会话分析")));
}

void MainWindow::showPacketDetail(int row){
    if(row<0||row>=ui->tablePackets->rowCount()){
        ui->txtPacketDetail->clear();ui->txtPacketHex->clear();ui->txtPacketBusiness->clear();return;
    }
    auto* item=ui->tablePackets->item(row,0);
    if(!item){ui->txtPacketDetail->clear();return;}
    const QVariant packetValue=item->data(Qt::UserRole+1);
    if(packetValue.canConvert<ParsedPacket>()){
        const ParsedPacket p=packetValue.value<ParsedPacket>();
        ui->txtPacketDetail->setPlainText(packetDetailText(p));
        ui->txtPacketHex->setPlainText(packetHexText(p));
        ui->txtPacketBusiness->setPlainText(packetBusinessText(p));
    }else{
        ui->txtPacketDetail->setPlainText(item->data(Qt::UserRole).toString());
        ui->txtPacketHex->clear();ui->txtPacketBusiness->clear();
    }
}

void MainWindow::renderFieldDiagnosis(){
    const FieldDiagnosisReport field=currentFieldReport();
    ui->txtFieldDiagnosis->setPlainText(currentLayeredReport());
    ui->txtTcpSessions->setPlainText(ChannelAnalyzer::tcpSessionReport(m_masterChannelEvidence,QStringLiteral("主站 TCP 会话"))
        +QStringLiteral("\n")
        +ChannelAnalyzer::tcpSessionReport(m_terminalChannelEvidence,QStringLiteral("终端 TCP 会话")));
    ui->labelOverallConclusion->setText(QStringLiteral("综合结论：%1").arg(field.overallConclusion));
    const QList<LayerDiagnosis> internalLayers=currentSixLayers();
    auto layerAt=[&internalLayers](int index)->LayerDiagnosis{
        return (index>=0&&index<internalLayers.size())?internalLayers.at(index):LayerDiagnosis{};
    };
    const LayerDiagnosis moduleLayer=layerAt(0);
    const LayerDiagnosis simLayer=layerAt(1);
    const LayerDiagnosis registrationLayer=layerAt(2);
    const LayerDiagnosis wanLayer=layerAt(3);
    const QList<LayerDiagnosis> layers=currentPresentationLayers();
    const QString wanIface=!m_discoveredWanIfname.isEmpty()?m_discoveredWanIfname:m_lastStatus.wanIfname;
    const QString usableWanIface=ConnectivityProbe::isUsableWanInterfaceName(wanIface)?wanIface:QString();
    const QString candidateWanIp=ConnectivityProbe::isUsableWanIpv4(m_lastStatus.wanIp)?m_lastStatus.wanIp:
        (ConnectivityProbe::isUsableWanIpv4(m_discoveredWanIp)?m_discoveredWanIp:QString());
    const bool validWanIp=ConnectivityProbe::isUsableWanIpv4(candidateWanIp);
    LayerState wanCardState=wanLayer.state;
    if((wanCardState==LayerState::Unknown||wanCardState==LayerState::NotTested)&&!usableWanIface.isEmpty())wanCardState=validWanIp?LayerState::Normal:LayerState::Warning;
    const bool wanInventoryAttempted=m_lastStatus.defaultRouteChecked;
    const bool moduleSkippedAfterWanFailure=wanInventoryAttempted && !m_lastStatus.moduleProbeAttempted && m_lastStatus.moduleName.isEmpty();
    const QString moduleCardValue=moduleSkippedAfterWanFailure?QStringLiteral("未测试"):moduleCardText(m_lastStatus.moduleName,moduleLayer.state);
    const LayerState moduleCardState=moduleSkippedAfterWanFailure?LayerState::NotTested:moduleLayer.state;
    const QString simCardValue=moduleSkippedAfterWanFailure?QStringLiteral("未测试"):cardStateText(simLayer.state);
    const LayerState simCardState=moduleSkippedAfterWanFailure?LayerState::NotTested:simLayer.state;
    const QString registrationCardValue=moduleSkippedAfterWanFailure?QStringLiteral("未测试"):cardStateText(registrationLayer.state);
    const LayerState registrationCardState=moduleSkippedAfterWanFailure?LayerState::NotTested:registrationLayer.state;
    const QString wanCardValue=!usableWanIface.isEmpty()?usableWanIface:(wanInventoryAttempted?QStringLiteral("未识别"):cardStateText(wanLayer.state));
    const LayerState effectiveWanCardState=!usableWanIface.isEmpty()?LayerState::Normal:(wanInventoryAttempted?LayerState::Unknown:wanLayer.state);
    const QString wanIpCardValue=validWanIp?candidateWanIp:(wanInventoryAttempted?QStringLiteral("未识别"):QStringLiteral("未测试"));
    setStatusCard(ui->labelCardModule,QStringLiteral("模组"),moduleCardValue,moduleCardState);
    setStatusCard(ui->labelCardSim,QStringLiteral("SIM"),simCardValue,simCardState);
    setStatusCard(ui->labelCardRegistration,QStringLiteral("网络注册"),registrationCardValue,registrationCardState);
    setStatusCard(ui->labelCardWan,QStringLiteral("WAN"),wanCardValue,effectiveWanCardState);
    setStatusCard(ui->labelCardWanIp,QStringLiteral("WAN IP"),wanIpCardValue,validWanIp?LayerState::Normal:(wanInventoryAttempted?LayerState::Unknown:wanCardState));
    const QString wanIpSource=(!m_discoveredWanIpSource.isEmpty()&&candidateWanIp==m_discoveredWanIp)?m_discoveredWanIpSource:QStringLiteral("日志/wan_ipaddr");
    ui->labelCardWanIp->setToolTip(validWanIp?QStringLiteral("WAN IP来源：%1").arg(wanIpSource):QStringLiteral("尚未获取有效WAN IP"));
    QStringList signalParts;
    if(m_lastStatus.rsrp!=999)signalParts<<QStringLiteral("RSRP %1 dBm").arg(m_lastStatus.rsrp);
    if(m_lastStatus.sinr!=999)signalParts<<QStringLiteral("SINR %1 dB").arg(m_lastStatus.sinr);
    QString signalText;
    LayerState signalState=LayerState::Unknown;
    const bool rsrpPlausible=m_lastStatus.rsrp>=-160&&m_lastStatus.rsrp<=-40;
    const bool sinrPlausible=m_lastStatus.sinr>=-30&&m_lastStatus.sinr<=50;
    if(!signalParts.isEmpty()){
        signalText=signalParts.join(QStringLiteral(" | "));
        signalState=((rsrpPlausible&&m_lastStatus.rsrp<=-110)||(sinrPlausible&&m_lastStatus.sinr<0))?LayerState::Warning:LayerState::Normal;
    }else if(m_lastStatus.moduleProbeAttempted){
        signalText=QStringLiteral("未识别");
    }else{
        signalText=QStringLiteral("未测试");
        signalState=LayerState::NotTested;
    }
    setStatusCard(ui->labelCardSignal,QStringLiteral("无线信号"),signalText,signalState);
    const int selected=ui->tableLayerStatus->currentRow();
    ui->tableLayerStatus->setRowCount(layers.size());
    for(int row=0;row<layers.size();++row){
        const LayerDiagnosis& d=layers.at(row);
        auto* layerItem=new QTableWidgetItem(layerTitle(d.layer));
        auto* stateItem=new QTableWidgetItem(layerStateText(d.state));
        auto* conclusionItem=new QTableWidgetItem(d.conclusion);
        stateItem->setTextAlignment(Qt::AlignCenter);
        QFont stateFont=stateItem->font();stateFont.setBold(true);stateItem->setFont(stateFont);
        QColor fg(QStringLiteral("#52606d")),bg(QStringLiteral("#eef2f6"));
        switch(d.state){
        case LayerState::Normal:fg=QColor(QStringLiteral("#176b46"));bg=QColor(QStringLiteral("#e8f5ee"));break;
        case LayerState::Warning:fg=QColor(QStringLiteral("#8a5a00"));bg=QColor(QStringLiteral("#fff3d1"));break;
        case LayerState::Error:fg=QColor(QStringLiteral("#a52a22"));bg=QColor(QStringLiteral("#fdebea"));break;
        case LayerState::Unknown:fg=QColor(QStringLiteral("#52606d"));bg=QColor(QStringLiteral("#eef2f6"));break;
        case LayerState::NotTested:fg=QColor(QStringLiteral("#6f7d8a"));bg=QColor(QStringLiteral("#f4f6f8"));break;
        }
        stateItem->setForeground(QBrush(fg));stateItem->setBackground(QBrush(bg));
        ui->tableLayerStatus->setItem(row,0,layerItem);
        ui->tableLayerStatus->setItem(row,1,stateItem);
        ui->tableLayerStatus->setItem(row,2,conclusionItem);
        ui->tableLayerStatus->setRowHeight(row,32);
    }
    const int row=(selected>=0&&selected<layers.size())?selected:(layers.isEmpty()?-1:0);
    if(row>=0){ui->tableLayerStatus->selectRow(row);showLayerDetail(row);}
    updateFieldSummary();
}

void MainWindow::updateStats(const CaptureStats& s){
    m_lastCaptureStats=s;
    if(m_capCtrl && m_capCtrl->isRunning()){
        if(s.totalPackets>0 && m_captureNoTrafficTimer)m_captureNoTrafficTimer->stop();
        updateCaptureActivityState(s.totalPackets>0?QStringLiteral("最近持续收到匹配报文"):QStringLiteral("当前暂无匹配流量"),LayerState::Normal);
    }
    const ChannelEvidence tcpEvidence=m_packetChannelAnalyzer.evidence();
    quint64 normal=0,noResponse=0,refused=0,reset=0,oneWay=0;
    for(const TcpSessionEvidence& session:tcpEvidence.tcpSessions){
        const bool anyRst=session.rstFromInitiator>0||session.rstFromResponder>0;
        const bool bothPayload=session.payloadPacketsFromInitiator>0&&session.payloadPacketsFromResponder>0;
        const bool anyPayload=session.payloadPacketsFromInitiator>0||session.payloadPacketsFromResponder>0;
        if(anyRst){
            if(session.synCount>0&&!session.handshakeComplete&&session.synAckCount==0&&session.rstFromResponder>0)++refused;
            else ++reset;
        }else if(session.synCount>0&&session.synAckCount==0){
            ++noResponse;
        }else if(session.handshakeComplete||bothPayload){
            ++normal;
        }else if(anyPayload){
            ++oneWay;
        }
    }
    ui->txtStats->setPlainText(QStringLiteral(
        "总包数：%1\n总字节：%2\n\nTCP：%3\nUDP：%4\nICMP：%5\n\nSYN：%6\nRST：%7\nFIN：%8\n疑似重传：%9\n\nTCP会话：%10\n正常/双向：%11\n无应答：%12\n被拒绝：%13\nRST异常：%14\n仅单向/证据不足：%15\n\nICMP请求/响应：%16 / %17")
        .arg(s.totalPackets).arg(s.totalBytes).arg(s.tcpPackets).arg(s.udpPackets).arg(s.icmpPackets)
        .arg(s.tcpSyn).arg(s.tcpRst).arg(s.tcpFin).arg(s.suspectedRetransmissions)
        .arg(tcpEvidence.tcpSessions.size()).arg(normal).arg(noResponse).arg(refused).arg(reset).arg(oneWay)
        .arg(s.icmpEchoRequests).arg(s.icmpEchoReplies));
}


void MainWindow::updateFieldSummary()
{
    if(!m_fieldSummaryPanel||!m_fieldSummaryStatus||!m_fieldSummaryStage||!m_fieldSummaryNext)return;

    const bool workflow=m_workflow&&m_workflow->isRunning();
    const QString conclusion=currentFieldReport().overallConclusion.trimmed();
    const QList<LayerDiagnosis> layers=currentPresentationLayers();

    LayerState overall=LayerState::Unknown;
    int worstRank=-1;
    QString worstTitle;
    QString worstConclusion;
    for(const LayerDiagnosis& layer:layers){
        const int rank=layerRank(layer.state);
        if(rank>worstRank && layer.state!=LayerState::NotTested){
            worstRank=rank;
            overall=layer.state;
            worstTitle=layerTitle(layer.layer);
            worstConclusion=layer.conclusion.trimmed();
        }
    }
    if(worstRank<0){
        overall=LayerState::NotTested;
        worstTitle=QStringLiteral("尚未开始检测");
    }

    QString statusText;
    QString statusState;
    switch(overall){
    case LayerState::Normal: statusText=QStringLiteral("系统基本正常"); statusState=QStringLiteral("normal"); break;
    case LayerState::Warning: statusText=QStringLiteral("存在需要关注项"); statusState=QStringLiteral("warning"); break;
    case LayerState::Error: statusText=QStringLiteral("发现异常"); statusState=QStringLiteral("error"); break;
    case LayerState::NotTested: statusText=QStringLiteral("等待诊断"); statusState=QStringLiteral("untested"); break;
    default: statusText=QStringLiteral("状态待确认"); statusState=QStringLiteral("unknown"); break;
    }
    if(workflow){
        statusText=QStringLiteral("正在诊断…");
        statusState=QStringLiteral("running");
    }

    QString stageText=QStringLiteral("待机");
    if(workflow && m_workflow)stageText=FieldWorkflowController::stepText(m_workflow->step());
    else if(m_controlLoggedIn)stageText=QStringLiteral("设备已连接，可开始现场诊断");
    else stageText=QStringLiteral("请先连接路由器");

    QString nextText;
    if(workflow){
        nextText=QStringLiteral("请保持设备连接，诊断完成后查看异常层和建议");
    }else if(overall==LayerState::Error){
        nextText=QStringLiteral("优先处理：%1").arg(worstTitle);
        if(!worstConclusion.isEmpty())nextText+=QStringLiteral(" · %1").arg(worstConclusion);
    }else if(overall==LayerState::Warning){
        nextText=QStringLiteral("建议查看：%1 的证据和处置建议").arg(worstTitle);
    }else if(overall==LayerState::NotTested){
        nextText=m_controlLoggedIn?QStringLiteral("点击“一键现场诊断”，自动完成核心链路检查"):QStringLiteral("连接设备后再开始诊断");
    }else{
        nextText=QStringLiteral("核心链路未发现明显异常，可继续进行抓包或协议分析");
    }
    if(!conclusion.isEmpty() && overall!=LayerState::Error && overall!=LayerState::Warning && !workflow)
        nextText=conclusion;

    m_fieldSummaryStatus->setText(statusText);
    m_fieldSummaryStatus->setProperty("state",statusState);
    m_fieldSummaryStatus->style()->unpolish(m_fieldSummaryStatus);
    m_fieldSummaryStatus->style()->polish(m_fieldSummaryStatus);
    m_fieldSummaryStatus->update();
    m_fieldSummaryStage->setText(stageText);
    m_fieldSummaryNext->setText(nextText);
    m_fieldSummaryPanel->setProperty("state",statusState);
    m_fieldSummaryPanel->style()->unpolish(m_fieldSummaryPanel);
    m_fieldSummaryPanel->style()->polish(m_fieldSummaryPanel);
}

void MainWindow::setupRc13Workspace()
{
    // 现场运维摘要：把“当前是否正常、做到哪一步、下一步干什么”放在首屏，
    // 具体证据仍保留在下面的分层诊断区域，避免现场人员在日志里找结论。
    m_fieldSummaryPanel=new QWidget(ui->tabFieldDiagnosis);
    m_fieldSummaryPanel->setObjectName(QStringLiteral("fieldSummaryPanel"));
    m_fieldSummaryPanel->setProperty("state",QStringLiteral("unknown"));
    auto* summaryLayout=new QHBoxLayout(m_fieldSummaryPanel);
    summaryLayout->setContentsMargins(14,10,14,10);
    summaryLayout->setSpacing(16);

    auto makeTitle=[this](const QString& title,QWidget* parent){
        auto* label=new QLabel(title,parent);
        label->setObjectName(QStringLiteral("fieldSummaryTitle"));
        label->setProperty("summaryRole",QStringLiteral("title"));
        return label;
    };
    auto makeValue=[this](QWidget* parent){
        auto* label=new QLabel(parent);
        label->setWordWrap(true);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        return label;
    };

    auto* statusBox=new QWidget(m_fieldSummaryPanel);
    auto* statusLayout=new QVBoxLayout(statusBox);
    statusLayout->setContentsMargins(0,0,0,0);statusLayout->setSpacing(2);
    statusLayout->addWidget(makeTitle(QStringLiteral("现场状态"),statusBox));
    m_fieldSummaryStatus=makeValue(statusBox);
    m_fieldSummaryStatus->setObjectName(QStringLiteral("fieldSummaryStatus"));
    m_fieldSummaryStatus->setText(QStringLiteral("等待诊断"));
    statusLayout->addWidget(m_fieldSummaryStatus);

    auto* stageBox=new QWidget(m_fieldSummaryPanel);
    auto* stageLayout=new QVBoxLayout(stageBox);
    stageLayout->setContentsMargins(0,0,0,0);stageLayout->setSpacing(2);
    stageLayout->addWidget(makeTitle(QStringLiteral("当前阶段"),stageBox));
    m_fieldSummaryStage=makeValue(stageBox);
    m_fieldSummaryStage->setObjectName(QStringLiteral("fieldSummaryStage"));
    stageLayout->addWidget(m_fieldSummaryStage);

    auto* nextBox=new QWidget(m_fieldSummaryPanel);
    auto* nextLayout=new QVBoxLayout(nextBox);
    nextLayout->setContentsMargins(0,0,0,0);nextLayout->setSpacing(2);
    nextLayout->addWidget(makeTitle(QStringLiteral("下一步建议"),nextBox));
    m_fieldSummaryNext=makeValue(nextBox);
    m_fieldSummaryNext->setObjectName(QStringLiteral("fieldSummaryNext"));
    nextLayout->addWidget(m_fieldSummaryNext);

    summaryLayout->addWidget(statusBox,0);
    summaryLayout->addWidget(stageBox,1);
    summaryLayout->addWidget(nextBox,3);
    ui->fieldTabLayout->insertWidget(0,m_fieldSummaryPanel);
    updateFieldSummary();

    ui->btnOneClickDiagnosis->setMinimumHeight(38);
    ui->btnOneClickDiagnosis->setToolTip(QStringLiteral("现场首选入口：自动完成设备发现、WAN、模组/SIM、主站/终端链路及业务数据诊断"));
    ui->btnCancelOneClick->setToolTip(QStringLiteral("立即停止当前一键诊断，不影响已采集的证据和历史记录"));
    ui->btnConnect->setToolTip(QStringLiteral("连接路由器控制台；连接成功后不会自动开始扫描"));
    ui->btnDisconnect->setToolTip(QStringLiteral("断开当前路由器连接和相关诊断会话"));

    auto* toggle=new QPushButton(QStringLiteral("折叠连接区"),this);
    toggle->setObjectName(QStringLiteral("btnToggleRouterConnectionCollapsed"));
    ui->gridConnection->addWidget(toggle,0,10);
    connect(toggle,&QPushButton::clicked,this,[this]{setRouterConnectionCollapsed(!ui->groupConnection->property("rc13Collapsed").toBool());});

    auto* compactBar=new QWidget(ui->groupConnection);
    compactBar->setObjectName(QStringLiteral("compactConnectionBar"));
    auto* compactLayout=new QHBoxLayout(compactBar);
    compactLayout->setContentsMargins(0,0,0,0);
    compactLayout->setSpacing(8);
    auto* compact=new QLabel(compactBar);
    compact->setObjectName(QStringLiteral("labelConnectionCompact"));
    compact->setWordWrap(false);
    compact->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Preferred);
    auto* compactConnect=new QPushButton(QStringLiteral("连接"),compactBar);
    compactConnect->setObjectName(QStringLiteral("btnCompactConnect"));
    compactConnect->setMinimumWidth(82);
    auto* compactDisconnect=new QPushButton(QStringLiteral("断开"),compactBar);
    compactDisconnect->setObjectName(QStringLiteral("btnCompactDisconnect"));
    compactDisconnect->setMinimumWidth(82);
    auto* compactExpand=new QPushButton(QStringLiteral("展开连接区"),compactBar);
    compactExpand->setObjectName(QStringLiteral("btnCompactExpandConnection"));
    compactExpand->setMinimumWidth(96);
    compactLayout->addWidget(compact,1);
    compactLayout->addWidget(compactConnect);
    compactLayout->addWidget(compactDisconnect);
    compactLayout->addWidget(compactExpand);
    compactBar->hide();
    ui->gridConnection->addWidget(compactBar,3,0,1,12);
    connect(compactConnect,&QPushButton::clicked,this,[this]{if(ui->btnConnect->isEnabled())ui->btnConnect->click();});
    connect(compactDisconnect,&QPushButton::clicked,this,[this]{if(ui->btnDisconnect->isEnabled())ui->btnDisconnect->click();});
    connect(compactExpand,&QPushButton::clicked,this,[this]{setRouterConnectionCollapsed(false);});

    auto* fieldAdvancedPanel=new QWidget(ui->groupFieldInput);
    fieldAdvancedPanel->setObjectName(QStringLiteral("fieldAdvancedPanel"));
    auto* fieldAdvancedLayout=new QHBoxLayout(fieldAdvancedPanel);
    fieldAdvancedLayout->setContentsMargins(0,0,0,0);
    fieldAdvancedLayout->setSpacing(8);
    ui->gridFieldInput->removeWidget(ui->labelAutoCaptureSeconds);
    ui->gridFieldInput->removeWidget(ui->spinAutoCaptureSeconds);
    ui->gridFieldInput->removeWidget(ui->labelExpectedConnectionSeconds);
    ui->gridFieldInput->removeWidget(ui->spinExpectedConnectionSeconds);
    fieldAdvancedLayout->addWidget(ui->labelAutoCaptureSeconds);
    fieldAdvancedLayout->addWidget(ui->spinAutoCaptureSeconds);
    fieldAdvancedLayout->addSpacing(16);
    fieldAdvancedLayout->addWidget(ui->labelExpectedConnectionSeconds);
    fieldAdvancedLayout->addWidget(ui->spinExpectedConnectionSeconds);
    fieldAdvancedLayout->addStretch(1);
    auto* fieldAdvancedToggle=new QPushButton(QStringLiteral("高级参数"),ui->groupFieldInput);
    fieldAdvancedToggle->setObjectName(QStringLiteral("btnToggleFieldAdvanced"));
    fieldAdvancedToggle->setToolTip(QStringLiteral("高级参数已直接显示"));
    fieldAdvancedToggle->hide();
    fieldAdvancedPanel->show();

    auto* filterBar=new QWidget(this);
    filterBar->setObjectName(QStringLiteral("captureQuickFilterBar"));
    auto* filterLayout=new QHBoxLayout(filterBar);filterLayout->setContentsMargins(0,0,0,0);filterLayout->setSpacing(6);
    auto* kind=new QComboBox(filterBar);kind->setObjectName(QStringLiteral("comboCaptureQuickFilter"));
    kind->addItems({QStringLiteral("全部"),QStringLiteral("SYN"),QStringLiteral("RST"),QStringLiteral("Payload"),QStringLiteral("IEC104"),QStringLiteral("异常")});
    auto* search=new QLineEdit(filterBar);search->setObjectName(QStringLiteral("editCaptureQuickSearch"));search->setPlaceholderText(QStringLiteral("搜索 IP / 端口 / Info / HEX"));
    filterLayout->addWidget(new QLabel(QStringLiteral("快速过滤"),filterBar));filterLayout->addWidget(kind);filterLayout->addWidget(search,1);
    if(auto* v=qobject_cast<QVBoxLayout*>(ui->tabRealtimeCapture->layout()))v->insertWidget(2,filterBar);
    connect(kind,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){refreshCaptureQuickFilter();});
    connect(search,&QLineEdit::textChanged,this,[this](const QString&){refreshCaptureQuickFilter();});

    m_fieldEvidenceTree=new QTreeWidget(this);m_fieldEvidenceTree->setObjectName(QStringLiteral("treeFieldEvidence"));
    m_fieldEvidenceTree->setHeaderLabels({QStringLiteral("证据树"),QStringLiteral("内容")});
    m_fieldEvidenceTree->setMinimumHeight(120);
    if(auto* lay=qobject_cast<QVBoxLayout*>(ui->txtLayerDetail->parentWidget()->layout())){
        lay->insertWidget(0,m_fieldEvidenceTree,1);
        auto* detailToggle=new QPushButton(QStringLiteral("展开层详情 ▼"),ui->txtLayerDetail->parentWidget());
        detailToggle->setObjectName(QStringLiteral("btnToggleLayerDetail"));
        detailToggle->setToolTip(QStringLiteral("按需显示当前诊断层的完整结论与建议"));
        lay->insertWidget(1,detailToggle);
        ui->txtLayerDetail->hide();
        connect(detailToggle,&QPushButton::clicked,this,[this,detailToggle]{
            const bool show=ui->txtLayerDetail->isHidden();
            detailToggle->setProperty("userToggled",true);
            ui->txtLayerDetail->setVisible(show);
            detailToggle->setText(show?QStringLiteral("收起层详情 ▲"):QStringLiteral("展开层详情 ▼"));
        });
        connect(m_fieldEvidenceTree,&QTreeWidget::itemClicked,this,[this,detailToggle](QTreeWidgetItem*,int){
            detailToggle->setProperty("userToggled",true);
            ui->txtLayerDetail->show();
            detailToggle->setText(QStringLiteral("收起层详情 ▲"));
        });
    }

    const QList<QLabel*> cards={ui->labelCardWan,ui->labelCardModule,ui->labelCardSim,ui->labelCardRegistration,ui->labelCardWanIp,ui->labelCardSignal};
    for(QLabel* card:cards){card->setCursor(Qt::PointingHandCursor);card->installEventFilter(this);card->setToolTip(card->toolTip()+QStringLiteral("\n单击查看对应详情"));}
}

void MainWindow::setRouterConnectionCollapsed(bool collapsed)
{
    ui->groupConnection->setProperty("rc13Collapsed",collapsed);
    const QString compactText=QStringLiteral("%1  %2:%3 | %4 | %5")
        .arg(m_controlLoggedIn?QStringLiteral("已连接"):QStringLiteral("未连接"),ui->editHost->text().trimmed())
        .arg(ui->spinPort->value()).arg(ui->comboRouterConnectionMode->currentText(),ui->editUser->text());
    if(auto* compact=ui->groupConnection->findChild<QLabel*>(QStringLiteral("labelConnectionCompact")))compact->setText(compactText);
    if(auto* compactBar=ui->groupConnection->findChild<QWidget*>(QStringLiteral("compactConnectionBar")))compactBar->setVisible(collapsed);
    auto* toggle=ui->groupConnection->findChild<QPushButton*>(QStringLiteral("btnToggleRouterConnectionCollapsed"));
    const QList<QWidget*> fullControls={ui->labelRouterConnectionMode,ui->comboRouterConnectionMode,ui->labelUser,ui->editUser,ui->labelPassword,ui->editPassword,ui->labelDefaultAccount,ui->labelConnectionStateTitle,ui->labelConnectionState,ui->btnConnect,ui->btnDisconnect,toggle};
    for(QWidget* w:fullControls)if(w)w->setVisible(!collapsed);
    const bool serial=routerSerialMode();
    ui->labelHost->setVisible(!collapsed&&!serial);
    ui->editHost->setVisible(!collapsed&&!serial);
    ui->labelPort->setVisible(!collapsed&&!serial);
    ui->spinPort->setVisible(!collapsed&&!serial);
    ui->labelHistory->setVisible(!collapsed&&!serial);
    ui->comboConnectionHistory->setVisible(!collapsed&&!serial);
    ui->serialSettingsPanel->setVisible(!collapsed&&serial);
    if(toggle)toggle->setText(QStringLiteral("折叠连接区"));
    ui->gridConnection->setContentsMargins(12,collapsed?8:14,12,collapsed?6:10);
    ui->gridConnection->setVerticalSpacing(collapsed?0:7);
    ui->groupConnection->setMinimumHeight(0);
    ui->groupConnection->setMaximumHeight(collapsed?72:QWIDGETSIZE_MAX);
    ui->groupConnection->updateGeometry();
}

bool MainWindow::packetMatchesCaptureQuickFilter(const ParsedPacket& packet,const QString& search) const
{
    const auto* kind=ui->tabRealtimeCapture->findChild<QComboBox*>(QStringLiteral("comboCaptureQuickFilter"));
    const QString mode=kind?kind->currentText():QStringLiteral("全部");
    const QString info=packet.summary;
    const QString protocol=packet.protocol;
    const QString rowText=packet.sourceIp+QLatin1Char(':')+QString::number(packet.sourcePort)
        +QLatin1Char(' ')+packet.destinationIp+QLatin1Char(':')+QString::number(packet.destinationPort)
        +QLatin1Char(' ')+protocol+QLatin1Char(' ')+info;
    bool matches=(mode==QStringLiteral("全部"))
        ||(mode==QStringLiteral("SYN")&&info.contains(QStringLiteral("SYN"),Qt::CaseInsensitive))
        ||(mode==QStringLiteral("RST")&&info.contains(QStringLiteral("RST"),Qt::CaseInsensitive))
        ||(mode==QStringLiteral("Payload")&&packet.tcpPayloadLength>0)
        ||(mode==QStringLiteral("IEC104")&&(rowText.contains(QStringLiteral("104"),Qt::CaseInsensitive)))
        ||(mode==QStringLiteral("异常")&&(info.contains(QStringLiteral("RST"),Qt::CaseInsensitive)
            ||info.contains(QStringLiteral("重传"))||info.contains(QStringLiteral("异常"))));
    const QString query=search.trimmed();
    if(matches&&!query.isEmpty())
        matches=rowText.contains(query,Qt::CaseInsensitive)||QString::fromLatin1(packet.payload.toHex(' ')).contains(query,Qt::CaseInsensitive);
    return matches;
}

void MainWindow::refreshCaptureQuickFilter()
{
    const auto* searchEdit=ui->tabRealtimeCapture->findChild<QLineEdit*>(QStringLiteral("editCaptureQuickSearch"));
    const QString query=searchEdit?searchEdit->text():QString();
    for(int r=0;r<ui->tablePackets->rowCount();++r){
        bool matches=false;
        if(const auto* item=ui->tablePackets->item(r,0)){
            const QVariant packetValue=item->data(Qt::UserRole+1);
            if(packetValue.canConvert<ParsedPacket>())matches=packetMatchesCaptureQuickFilter(packetValue.value<ParsedPacket>(),query);
        }
        // Legacy/imported rows without a stored packet model still participate in text search.
        if(!matches && !query.trimmed().isEmpty()){
            QString rowText;
            for(int c=2;c<=6;++c)if(auto* cell=ui->tablePackets->item(r,c))rowText+=cell->text()+QLatin1Char(' ');
            matches=rowText.contains(query,Qt::CaseInsensitive);
        }
        ui->tablePackets->setRowHidden(r,!matches);
    }
}

void MainWindow::populateEvidenceTree(const LayerDiagnosis& layer)
{
    if(!m_fieldEvidenceTree)return;m_fieldEvidenceTree->clear();
    auto* root=new QTreeWidgetItem(m_fieldEvidenceTree,{layerTitle(layer.layer),layer.conclusion});
    auto* state=new QTreeWidgetItem(root,{QStringLiteral("状态"),QStringLiteral("%1 / 置信度%2").arg(layerStateText(layer.state),confidenceText(layer.confidence))});Q_UNUSED(state);
    auto* evRoot=new QTreeWidgetItem(root,{QStringLiteral("证据"),QString::number(layer.evidence.size())});for(const QString& ev:layer.evidence)new QTreeWidgetItem(evRoot,{QStringLiteral("证据"),ev});
    auto* tipRoot=new QTreeWidgetItem(root,{QStringLiteral("建议"),QString::number(layer.suggestions.size())});for(const QString& tip:layer.suggestions)new QTreeWidgetItem(tipRoot,{QStringLiteral("建议"),tip});
    m_fieldEvidenceTree->expandToDepth(1);
}

void MainWindow::openStatusCardDetail(QObject* card)
{
    if(card==ui->labelCardWan||card==ui->labelCardWanIp){ui->mainTabs->setCurrentWidget(ui->tabFieldDiagnosis);showLayerDetail(1);} 
    else if(card==ui->labelCardModule||card==ui->labelCardSim||card==ui->labelCardRegistration){ui->mainTabs->setCurrentWidget(ui->tabFieldDiagnosis);showLayerDetail(0);} 
    else if(card==ui->labelCardSignal){ui->mainTabs->setCurrentWidget(ui->tabFieldDiagnosis);showLayerDetail(0);} 
}
