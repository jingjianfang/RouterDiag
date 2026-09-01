#include <QtTest>
#include <QComboBox>
#include <QCheckBox>
#include <QLineEdit>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QWidget>
#include <QVBoxLayout>
#include <QGridLayout>
#include "ui/DetachablePanelManager.h"
#include <QSpinBox>
#include <QTabWidget>
#include <QScrollArea>
#include "MainWindow.h"

class TestMainWindowUi : public QObject {
    Q_OBJECT
private slots:
    void defaultsToAdminAndFieldValues(){
        MainWindow w;
        auto* user=w.findChild<QLineEdit*>("editUser");
        auto* password=w.findChild<QLineEdit*>("editPassword");
        auto* masterPort=w.findChild<QSpinBox*>("spinMasterPort");
        auto* transport=w.findChild<QComboBox*>("comboTerminalTransport");
        auto* fullReport=w.findChild<QPlainTextEdit*>("txtFieldDiagnosis");
        auto* terminalIp=w.findChild<QLineEdit*>("editTerminalIp");
        auto* terminalPort=w.findChild<QSpinBox*>("spinTerminalPort");
        QVERIFY(user);QVERIFY(password);QVERIFY(masterPort);QVERIFY(transport);QVERIFY(fullReport);QVERIFY(terminalIp);QVERIFY(terminalPort);
        QCOMPARE(user->text(),QString("admin"));
        QCOMPARE(password->text(),QString("admin"));
        QCOMPARE(password->echoMode(),QLineEdit::Password);
        QCOMPARE(masterPort->value(),2404);
        QCOMPARE(terminalPort->value(),2404);
        QCOMPARE(w.windowTitle(),QString::fromUtf8("四信路由器通信诊断工具"));
        QCOMPARE(transport->count(),2);
        QCOMPARE(transport->itemText(0),QString::fromUtf8("网口"));
        QCOMPARE(transport->itemText(1),QString::fromUtf8("串口"));
        QVERIFY(terminalIp->toolTip().contains("br0"));
    }

    void routerConnectionOffersAutoSerialDefaults(){
        MainWindow w;
        auto* mode=w.findChild<QComboBox*>("comboRouterConnectionMode");
        auto* serialPanel=w.findChild<QWidget*>("serialSettingsPanel");
        auto* serialPort=w.findChild<QComboBox*>("comboPcSerialPort");
        auto* baud=w.findChild<QComboBox*>("comboSerialBaud");
        auto* data=w.findChild<QComboBox*>("comboSerialDataBits");
        auto* stop=w.findChild<QComboBox*>("comboSerialStopBits");
        auto* parity=w.findChild<QComboBox*>("comboSerialParity");
        auto* host=w.findChild<QLineEdit*>("editHost");
        QVERIFY(mode);QVERIFY(serialPanel);QVERIFY(serialPort);QVERIFY(baud);QVERIFY(data);QVERIFY(stop);QVERIFY(parity);QVERIFY(host);
        QCOMPARE(mode->count(),2);
        QCOMPARE(mode->itemText(0),QString::fromUtf8("网口 Telnet"));
        QCOMPARE(mode->itemText(1),QString::fromUtf8("串口 Telnet"));
        QCOMPARE(baud->currentText(),QStringLiteral("115200"));
        QCOMPARE(data->currentText(),QStringLiteral("8"));
        QCOMPARE(stop->currentText(),QStringLiteral("1"));
        QCOMPARE(parity->currentText(),QStringLiteral("N"));
        QVERIFY(serialPanel->isHidden());
        mode->setCurrentIndex(1);
        QCoreApplication::processEvents();
        QVERIFY(!serialPanel->isHidden());
        QVERIFY(host->isHidden());
    }

    void mainWorkflowUsesFourFocusedTabs(){
        MainWindow w;
        auto* tabs=w.findChild<QTabWidget*>("mainTabs");
        QVERIFY(tabs);
        QCOMPARE(tabs->count(),4);
        QCOMPARE(tabs->tabText(0),QString::fromUtf8("现场诊断"));
        QCOMPARE(tabs->tabText(1),QString::fromUtf8("实时抓包"));
        QCOMPARE(tabs->tabText(2),QString::fromUtf8("离线分析"));
        QCOMPARE(tabs->tabText(3),QString::fromUtf8("工具"));
        QVERIFY(w.findChild<QPushButton*>("btnOneClickDiagnosis"));
        QVERIFY(w.findChild<QPushButton*>("btnCancelOneClick"));
        QVERIFY(w.findChild<QTableWidget*>("tableLayerStatus"));
        QVERIFY(w.findChild<QPlainTextEdit*>("txtLayerDetail"));
        QVERIFY(w.findChild<QPlainTextEdit*>("txtTcpSessions"));
        QVERIFY(w.findChild<QPlainTextEdit*>("txtPacketDetail"));
    }

    void deviceInterfaceDetailsHideNonIfconfigSummaries(){
        MainWindow w;
        auto* wanSummary=w.findChild<QLabel*>("labelWanSummary");
        auto* autoStatus=w.findChild<QLabel*>("labelAutoDetectStatus");
        auto* interfaces=w.findChild<QTableWidget*>("tableInterfaces");
        QVERIFY(wanSummary);QVERIFY(autoStatus);QVERIFY(interfaces);
        QVERIFY(wanSummary->isHidden());
        QVERIFY(autoStatus->isHidden());
    }

    void unifiedCaptureModeHasWanMasterAndTerminal(){
        MainWindow w;
        auto* mode=w.findChild<QComboBox*>("comboCaptureMode");
        auto* target=w.findChild<QLineEdit*>("editCaptureTarget");
        auto* iface=w.findChild<QComboBox*>("comboCaptureInterface");
        auto* filter=w.findChild<QLineEdit*>("editFilter");
        QVERIFY(mode);QVERIFY(target);QVERIFY(iface);QVERIFY(filter);
        QVERIFY(iface->isEditable());
        QCOMPARE(mode->count(),4);
        QCOMPARE(mode->itemText(0),QString::fromUtf8("WAN 抓包"));
        QCOMPARE(mode->itemText(1),QString::fromUtf8("主站抓包"));
        QCOMPARE(mode->itemText(2),QString::fromUtf8("终端抓包"));
        QCOMPARE(mode->itemText(3),QString::fromUtf8("自定义抓包"));
    }

    void serialModeDisablesTerminalIpNetworkAction(){
        MainWindow w;
        auto* transport=w.findChild<QComboBox*>("comboTerminalTransport");
        auto* terminalIp=w.findChild<QLineEdit*>("editTerminalIp");
        auto* terminalIpLabel=w.findChild<QLabel*>("labelTerminalIp");
        auto* terminalPort=w.findChild<QSpinBox*>("spinTerminalPort");
        auto* terminalPortLabel=w.findChild<QLabel*>("labelTerminalPort");
        auto* terminalRole=w.findChild<QComboBox*>("comboTerminalRole");
        auto* terminalRoleLabel=w.findChild<QLabel*>("labelTerminalRole");
        auto* ping=w.findChild<QPushButton*>("btnPingTerminal");
        QVERIFY(transport);QVERIFY(terminalIp);QVERIFY(terminalIpLabel);QVERIFY(terminalPort);QVERIFY(terminalPortLabel);QVERIFY(terminalRole);QVERIFY(terminalRoleLabel);QVERIFY(ping);
        transport->setCurrentText(QString::fromUtf8("串口"));
        QCoreApplication::processEvents();
        QVERIFY(terminalIp->isHidden());
        QVERIFY(terminalIpLabel->isHidden());
        QVERIFY(terminalPort->isHidden());
        QVERIFY(terminalPortLabel->isHidden());
        QVERIFY(terminalRole->isHidden());
        QVERIFY(terminalRoleLabel->isHidden());
        QVERIFY(ping->isHidden());
        QVERIFY(terminalIp->toolTip().contains("DTS"));
        QVERIFY(terminalIp->toolTip().contains("ttyUSB"));
        auto* modeHint=w.findChild<QLabel*>("labelTerminalModeHint");
        QVERIFY(modeHint);
        QVERIFY(modeHint->text().isEmpty());
        QVERIFY(modeHint->isHidden());

        transport->setCurrentText(QString::fromUtf8("网口"));
        QCoreApplication::processEvents();
        QVERIFY(!terminalIp->isHidden());
        QVERIFY(!terminalIpLabel->isHidden());
        QVERIFY(!terminalPort->isHidden());
        QVERIFY(!terminalPortLabel->isHidden());
        QVERIFY(!terminalRole->isHidden());
        QVERIFY(!terminalRoleLabel->isHidden());
        QVERIFY(!ping->isHidden());
    }

    void layeredReportAndLayerTableAreInitialized(){
        MainWindow w;
        auto* fullReport=w.findChild<QPlainTextEdit*>("txtFieldDiagnosis");
        auto* layers=w.findChild<QTableWidget*>("tableLayerStatus");
        QVERIFY(fullReport);QVERIFY(layers);
        const QString text=fullReport->toPlainText();
        QVERIFY(text.contains(QString::fromUtf8("[1] 模组 / SIM / 网络注册")));
        QVERIFY(text.contains(QString::fromUtf8("[3] 主站与终端链路")));
        QVERIFY(text.contains(QString::fromUtf8("[4] 业务数据")));
        QVERIFY(!text.contains(QString::fromUtf8("[5] IEC101/IEC104")));
        QCOMPARE(layers->rowCount(),4);
        QVERIFY(!layers->verticalHeader()->isVisible());
    }

    void fieldOperationsRemainAvailableButAreGrouped(){
        MainWindow w;
        QVERIFY(w.findChild<QComboBox*>("comboConnectionHistory"));
        QVERIFY(w.findChild<QTableWidget*>("tableInterfaces"));
        QVERIFY(w.findChild<QPushButton*>("btnDisconnect"));
        QVERIFY(w.findChild<QPushButton*>("btnModuleLog"));
        QVERIFY(w.findChild<QPushButton*>("btnCommandWindow"));
        QVERIFY(w.findChild<QPushButton*>("btnNewPingWindow"));
        auto* runtime=w.findChild<QPlainTextEdit*>("txtDiagnosis");
        QVERIFY(runtime);
        QCOMPARE(runtime->placeholderText(),QString::fromUtf8("实时运行日志"));
    }

    void offlineTabProvidesTcpdumpTextToPcapConversion(){
        MainWindow w;
        auto* button=w.findChild<QPushButton*>("btnConvertTcpdumpText");
        QVERIFY(button);
        QVERIFY(button->text().contains(QString::fromUtf8("PCAP")));
    }

    void routerConnectionCollapseUsesSingleCompactRow(){
        MainWindow w;
        auto* group=w.findChild<QGroupBox*>("groupConnection");
        auto* toggle=w.findChild<QPushButton*>("btnToggleRouterConnectionCollapsed");
        auto* compactBar=w.findChild<QWidget*>("compactConnectionBar");
        auto* compactText=w.findChild<QLabel*>("labelConnectionCompact");
        auto* connectButton=w.findChild<QPushButton*>("btnCompactConnect");
        auto* disconnectButton=w.findChild<QPushButton*>("btnCompactDisconnect");
        auto* expandButton=w.findChild<QPushButton*>("btnCompactExpandConnection");
        QVERIFY(group);QVERIFY(toggle);QVERIFY(compactBar);QVERIFY(compactText);
        QVERIFY(connectButton);QVERIFY(disconnectButton);QVERIFY(expandButton);
        QVERIFY(compactBar->isHidden());
        toggle->click();
        QCoreApplication::processEvents();
        QVERIFY(!compactBar->isHidden());
        QVERIFY(compactText->text().contains(QStringLiteral("192.168.1.1:23")));
        QVERIFY(compactText->text().contains(QString::fromUtf8("网口 Telnet")));
        QVERIFY(w.findChild<QLineEdit*>("editHost")->isHidden());
        QVERIFY(w.findChild<QLabel*>("labelConnectionState")->isHidden());
        QVERIFY(toggle->isHidden());
        QVERIFY(group->maximumHeight()<=72);
        QCOMPARE(expandButton->text(),QString::fromUtf8("展开连接区"));
        expandButton->click();
        QCoreApplication::processEvents();
        QVERIFY(compactBar->isHidden());
        QVERIFY(!toggle->isHidden());
        QCOMPARE(group->maximumHeight(),QWIDGETSIZE_MAX);
    }

    void workspaceSelectorIsRemoved(){
        MainWindow w;
        QVERIFY(!w.findChild<QComboBox*>("comboWorkspacePreset"));
        QVERIFY(!w.findChild<QLabel*>("labelWorkspacePreset"));
        auto* tabs=w.findChild<QTabWidget*>("mainTabs");
        QVERIFY(tabs);
        QCOMPARE(tabs->count(),4);
    }

    void compactResponsiveLayoutKeepsConnectionControlsManaged(){
        MainWindow w;
        w.resize(1280,1024);
        w.show();
        QCoreApplication::processEvents();
        auto* group=w.findChild<QGroupBox*>("groupConnection");
        auto* toggle=w.findChild<QPushButton*>("btnToggleRouterConnectionCollapsed");
        auto* state=w.findChild<QLabel*>("labelConnectionState");
        QVERIFY(group);QVERIFY(toggle);QVERIFY(state);
        auto* grid=qobject_cast<QGridLayout*>(group->layout());
        QVERIFY(grid);
        QVERIFY2(grid->indexOf(toggle)>=0,"collapse button must remain managed after compact reflow");
        QVERIFY2(grid->indexOf(state)>=0,"connection state must remain managed after compact reflow");
    }

    void serialConnectionLayoutSurvivesResponsiveReflow(){
        MainWindow w;
        auto* mode=w.findChild<QComboBox*>("comboRouterConnectionMode");
        auto* host=w.findChild<QLineEdit*>("editHost");
        auto* hostLabel=w.findChild<QLabel*>("labelHost");
        auto* serialPanel=w.findChild<QWidget*>("serialSettingsPanel");
        QVERIFY(mode);QVERIFY(host);QVERIFY(hostLabel);QVERIFY(serialPanel);
        mode->setCurrentText(QString::fromUtf8("串口 Telnet"));
        w.resize(1280,900);w.show();QCoreApplication::processEvents();
        QVERIFY(host->isHidden());
        QVERIFY(hostLabel->isHidden());
        QVERIFY(!serialPanel->isHidden());
        w.resize(1500,900);QCoreApplication::processEvents();
        QVERIFY(host->isHidden());
        QVERIFY(hostLabel->isHidden());
        QVERIFY(!serialPanel->isHidden());
    }

    void spaciousLayoutKeepsSecondaryDetailsCollapsedByDefault(){
        MainWindow w;
        auto* deviceDetails=w.findChild<QWidget*>("deviceDetailsPanel");
        auto* deviceToggle=w.findChild<QPushButton*>("btnToggleDeviceDetails");
        auto* captureAdvanced=w.findChild<QWidget*>("captureAdvancedPanel");
        auto* captureToggle=w.findChild<QPushButton*>("btnToggleCaptureAdvanced");
        auto* runtimeLog=w.findChild<QGroupBox*>("groupRuntimeLog");
        auto* runtimeToggle=w.findChild<QPushButton*>("btnToggleRuntimeLog");
        QVERIFY(deviceDetails);QVERIFY(deviceToggle);QVERIFY(captureAdvanced);QVERIFY(captureToggle);QVERIFY(runtimeLog);QVERIFY(runtimeToggle);
        auto* directSave=w.findChild<QCheckBox*>("checkDirectSave");
        QVERIFY(directSave);
        QVERIFY(deviceDetails->isHidden());
        QVERIFY(!captureAdvanced->isHidden());
        QVERIFY(directSave->isHidden());
        QVERIFY(runtimeLog->isHidden());
        QVERIFY(deviceToggle->text().contains(QString::fromUtf8("详情")));
        QVERIFY(captureToggle->text().contains(QString::fromUtf8("高级")));
        QVERIFY(runtimeToggle->text().contains(QString::fromUtf8("运行日志")));
        deviceToggle->click();
        captureToggle->click();
        runtimeToggle->click();
        QVERIFY(!deviceDetails->isHidden());
        QVERIFY(!captureAdvanced->isHidden());
        QVERIFY(!directSave->isHidden());
        QVERIFY(!runtimeLog->isHidden());
        runtimeToggle->click();
        QVERIFY(runtimeLog->isHidden());
    }

    void deviceStatusUsesCompactSummaryCards(){
        MainWindow w;
        auto* wan=w.findChild<QLabel*>("labelCardWan");
        QVERIFY(wan);
        QCOMPARE(wan->text(),QString::fromUtf8("WAN\n未测试"));
        QVERIFY(w.findChild<QLabel*>("labelCardModule"));
        QVERIFY(w.findChild<QLabel*>("labelCardSim"));
        QVERIFY(w.findChild<QLabel*>("labelCardRegistration"));
        auto* wanIp=w.findChild<QLabel*>("labelCardWanIp");
        auto* signal=w.findChild<QLabel*>("labelCardSignal");
        QVERIFY(wanIp);QVERIFY(signal);
        QCOMPARE(wanIp->text(),QString::fromUtf8("WAN IP\n未测试"));
        QCOMPARE(signal->text(),QString::fromUtf8("无线信号\n未测试"));
        QVERIFY(w.findChild<QTableWidget*>("tableInterfaces"));
    }


    void realtimeCaptureNewTaskLivesInPanelHeader(){
        MainWindow w;
        auto* button=w.findChild<QPushButton*>("btnNewCaptureWindow");
        QVERIFY(button);
        QVERIFY(button->text().contains(QString::fromUtf8("新建抓包窗口")));
        QVERIFY(!button->toolTip().isEmpty());
        QVERIFY(button->parentWidget());
        QCOMPARE(button->parentWidget()->objectName(),QStringLiteral("detachablePanelHeader"));
    }

    void realtimeCaptureHasLivePacketAnalysisTabs(){
        MainWindow w;
        auto* follow=w.findChild<QCheckBox*>("checkFollowLatestPacket");
        auto* state=w.findChild<QLabel*>("labelCaptureState");
        auto* hex=w.findChild<QPlainTextEdit*>("txtPacketHex");
        auto* tcp=w.findChild<QPlainTextEdit*>("txtRealtimeTcpSessions");
        auto* business=w.findChild<QPlainTextEdit*>("txtPacketBusiness");
        QVERIFY(follow);QVERIFY(state);QVERIFY(hex);QVERIFY(tcp);QVERIFY(business);
        QVERIFY(follow->isChecked());
        QCOMPARE(state->text(),QString::fromUtf8("待机"));
    }

    void ethernetModeEnablesTerminalIpAction(){
        MainWindow w;
        auto* transport=w.findChild<QComboBox*>("comboTerminalTransport");
        auto* terminalIp=w.findChild<QLineEdit*>("editTerminalIp");
        auto* ping=w.findChild<QPushButton*>("btnPingTerminal");
        transport->setCurrentText(QString::fromUtf8("串口"));
        transport->setCurrentText(QString::fromUtf8("网口"));
        QCoreApplication::processEvents();
        QVERIFY(terminalIp->isEnabled());
        QVERIFY(!ping->isEnabled()); // 未连接路由器时网络操作保持禁用
    }
    void serialModeDisablesTerminalBr0CaptureMode(){
        MainWindow w;
        auto* transport=w.findChild<QComboBox*>("comboTerminalTransport");
        auto* captureMode=w.findChild<QComboBox*>("comboCaptureMode");
        auto* target=w.findChild<QLineEdit*>("editCaptureTarget");
        auto* plan=w.findChild<QLabel*>("labelCapturePlan");
        QVERIFY(transport);QVERIFY(captureMode);QVERIFY(target);QVERIFY(plan);
        transport->setCurrentText(QString::fromUtf8("串口"));
        captureMode->setCurrentText(QString::fromUtf8("终端抓包"));
        QCoreApplication::processEvents();
        QVERIFY(target->isHidden());
        QVERIFY(plan->text().contains(QString::fromUtf8("当前：")));
    }

    void closingFloatingPanelReattachesAndStaysVisible(){
        QWidget host;
        host.resize(900,600);
        auto* layout=new QVBoxLayout(&host);
        auto* panel=new QPlainTextEdit(&host);
        panel->setPlainText(QStringLiteral("live data"));
        layout->addWidget(panel);
        host.show();
        QCoreApplication::processEvents();

        DetachablePanelManager manager(panel,QStringLiteral("test panel"),QString(),&host);
        QWidget* wrapper=manager.container();
        QVERIFY(wrapper);
        manager.detachPanel();
        QCoreApplication::processEvents();
        QVERIFY(manager.isDetached());
        QVERIFY(wrapper->isWindow());

        wrapper->close();
        QTRY_VERIFY(!manager.isDetached());
        QCOMPARE(wrapper->parentWidget(),&host);
        QVERIFY(!wrapper->isWindow());
        QVERIFY(!wrapper->isHidden());
        QVERIFY(!panel->isHidden());
    }

    void compact1280UsesManagedFieldLayoutAndAdvancedPanel(){
        MainWindow w;
        w.resize(1280,1024);
        w.show();
        QCoreApplication::processEvents();
        QCOMPARE(w.findChild<QWidget*>("centralwidget")->property("responsiveLayoutMode").toString(),QStringLiteral("compact"));
        auto* grid=w.findChild<QGridLayout*>("gridFieldInput");
        auto* advanced=w.findChild<QWidget*>("fieldAdvancedPanel");
        auto* toggle=w.findChild<QPushButton*>("btnToggleFieldAdvanced");
        auto* masterRole=w.findChild<QComboBox*>("comboMasterRole");
        auto* terminalRole=w.findChild<QComboBox*>("comboTerminalRole");
        QVERIFY(grid);QVERIFY(advanced);QVERIFY(toggle);QVERIFY(masterRole);QVERIFY(terminalRole);
        QVERIFY(grid->indexOf(masterRole)>=0);
        QVERIFY(grid->indexOf(terminalRole)>=0);
        QVERIFY(grid->indexOf(advanced)>=0);
        QVERIFY(!advanced->isHidden());
        QVERIFY(toggle->isHidden());
    }

    void compactLayerDetailStartsCollapsedAndCanExpandOnDemand(){
        MainWindow w;
        w.resize(1280,1024);
        w.show();
        QCoreApplication::processEvents();
        auto* detail=w.findChild<QPlainTextEdit*>("txtLayerDetail");
        auto* toggle=w.findChild<QPushButton*>("btnToggleLayerDetail");
        QVERIFY(detail);QVERIFY(toggle);
        QVERIFY(detail->isHidden());
        toggle->click();
        QCoreApplication::processEvents();
        QVERIFY(!detail->isHidden());
    }



    void compactConnectionStatusDoesNotOverlapHistory(){
        MainWindow w;
        w.resize(1280,900);w.show();QCoreApplication::processEvents();
        auto* state=w.findChild<QLabel*>("labelConnectionState");
        auto* history=w.findChild<QComboBox*>("comboConnectionHistory");
        QVERIFY(state);QVERIFY(history);
        state->setText(QString::fromUtf8("登录/连接失败，已自动断开：控制连接登录失败：Telnet login timed out"));
        QCoreApplication::processEvents();
        QVERIFY(!state->geometry().intersects(history->geometry()));
    }

    void captureInterfaceSelectorUsesActualListAndManualInput(){
        MainWindow w;
        auto* iface=w.findChild<QComboBox*>("comboCaptureInterface");
        auto* refresh=w.findChild<QPushButton*>("btnRefreshCaptureInterfaces");
        auto* newWindow=w.findChild<QPushButton*>("btnNewCaptureWindow");
        QVERIFY(iface);QVERIFY(refresh);QVERIFY(newWindow);
        QVERIFY(iface->isEditable());
        QVERIFY(iface->count()<=1);
        iface->setEditText(QStringLiteral("tun0"));
        QCOMPARE(iface->currentText(),QStringLiteral("tun0"));
        QVERIFY(newWindow->text().contains(QString::fromUtf8("新建抓包窗口")));
    }

    void captureInterfaceSelectorIncludesAnyPseudoInterface(){
        MainWindow w;
        auto* iface=w.findChild<QComboBox*>("comboCaptureInterface");
        QVERIFY(iface);
        // `any` is a tcpdump pseudo-interface, not a synthetic router interface.
        QVERIFY(iface->findText(QStringLiteral("any"))>=0);
    }

    void captureModeHidesIrrelevantTargetFields(){
        MainWindow w;
        auto* mode=w.findChild<QComboBox*>("comboCaptureMode");
        auto* target=w.findChild<QLineEdit*>("editCaptureTarget");
        auto* targetLabel=w.findChild<QLabel*>("labelCaptureTarget");
        auto* port=w.findChild<QSpinBox*>("spinCapturePort");
        auto* portLabel=w.findChild<QLabel*>("labelCaptureBusinessPort");
        auto* filter=w.findChild<QLineEdit*>("editFilter");
        QVERIFY(mode);QVERIFY(target);QVERIFY(targetLabel);QVERIFY(port);QVERIFY(portLabel);QVERIFY(filter);
        mode->setCurrentIndex(0);QCoreApplication::processEvents();
        QVERIFY(target->isHidden());QVERIFY(port->isHidden());
        QVERIFY(!filter->isHidden());
        mode->setCurrentIndex(1);QCoreApplication::processEvents();
        QVERIFY(!target->isHidden());QVERIFY(!port->isHidden());
        mode->setCurrentIndex(3);QCoreApplication::processEvents();
        QVERIFY(target->isHidden());QVERIFY(port->isHidden());
        QVERIFY(!filter->isHidden());
    }

    void globalStopDiagnosisLivesOutsideTabs(){
        MainWindow w;
        auto* stop=w.findChild<QPushButton*>("btnGlobalStopDiagnosis");
        QVERIFY(stop);
        QCOMPARE(stop->text(),QString::fromUtf8("停止诊断"));
        QVERIFY(stop->isHidden());
        QVERIFY(stop->parentWidget());
        QVERIFY(stop->parentWidget()->inherits("QStatusBar"));
    }

    void serialTerminalShowsSeparatedSerialAndNetworkViews(){
        MainWindow w;
        auto* transport=w.findChild<QComboBox*>("comboTerminalTransport");
        auto* tabs=w.findChild<QTabWidget*>("packetDetailTabs");
        auto* serialLog=w.findChild<QPlainTextEdit*>("txtSerialCommunication");
        auto* timeline=w.findChild<QPlainTextEdit*>("txtSerialNetworkTimeline");
        QVERIFY(transport);QVERIFY(tabs);QVERIFY(serialLog);QVERIFY(timeline);
        transport->setCurrentText(QString::fromUtf8("串口"));
        QCoreApplication::processEvents();
        int serialIndex=tabs->indexOf(serialLog), timelineIndex=tabs->indexOf(timeline);
        QVERIFY(serialIndex>=0);QVERIFY(timelineIndex>=0);
        QVERIFY(tabs->isTabVisible(serialIndex));QVERIFY(tabs->isTabVisible(timelineIndex));
        QVERIFY(tabs->tabText(serialIndex).contains(QString::fromUtf8("串口通信")));
        QVERIFY(tabs->tabText(timelineIndex).contains(QString::fromUtf8("串口与网络时间线")));
    }

    void windowSupportsCompactResponsiveMode(){
        MainWindow w;
        QCOMPARE(w.minimumSize(),QSize(800,520));
        auto* scroll=w.findChild<QScrollArea*>("mainScrollArea");
        QVERIFY(scroll);
        QVERIFY(scroll->widgetResizable());
        w.resize(800,520);
        QCoreApplication::processEvents();
        auto* title=w.findChild<QLabel*>("labelProductTitle");
        auto* pingGroup=w.findChild<QGroupBox*>("groupPingResult");
        auto* pingOutput=w.findChild<QPlainTextEdit*>("txtPingResult");
        auto* captureState=w.findChild<QLabel*>("labelCaptureState");
        auto* packetTable=w.findChild<QTableWidget*>("tablePackets");
        QVERIFY(!title);QVERIFY(pingGroup);QVERIFY(pingOutput);QVERIFY(captureState);QVERIFY(packetTable);
        QVERIFY(!pingGroup->isVisible());
        QCOMPARE(packetTable->horizontalHeaderItem(5)->text(),QStringLiteral("Length(Payload)"));
    }

};

QTEST_MAIN(TestMainWindowUi)
#include "test_mainwindowui.moc"
