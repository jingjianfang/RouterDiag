#include "CaptureSessionWidget.h"
#include "capture/PacketCaptureController.h"
#include "diagnostic/DeviceDiscoveryController.h"
#include "telnet/TelnetClient.h"
#include "ui/DetachablePanelManager.h"

#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QSizePolicy>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QTimer>

CaptureSessionWidget::CaptureSessionWidget(const QString& title,const CaptureSessionConnectionParams& params,QWidget* parent)
    :QWidget(parent,Qt::Window),m_params(params)
{
    setAttribute(Qt::WA_DeleteOnClose,true);
    buildUi(title);

    if(m_params.serialShared){
        m_control=m_params.sharedControl;
        m_capture=m_params.sharedControl;
        m_controlLogged=m_captureLogged=(m_control && m_control->isConnected());
    }else{
        m_ownsClients=true;
        m_control=new TelnetClient(this);
        m_capture=new TelnetClient(this);
        connect(m_control,&TelnetClient::connected,this,[this]{m_control->login(m_params.user,m_params.password);});
        connect(m_capture,&TelnetClient::connected,this,[this]{m_capture->login(m_params.user,m_params.password);});
        connect(m_control,&TelnetClient::loginSucceeded,this,[this]{m_controlLogged=true;if(m_refreshPending)runInterfaceRefresh();tryStartController();});
        connect(m_capture,&TelnetClient::loginSucceeded,this,[this]{m_captureLogged=true;tryStartController();});
        connect(m_control,&TelnetClient::loginFailed,this,[this](const QString& e){m_pendingStart=false;m_state->setText(QStringLiteral("控制登录失败：%1").arg(e));emit captureSessionFailed(e);});
        connect(m_capture,&TelnetClient::loginFailed,this,[this](const QString& e){m_pendingStart=false;m_state->setText(QStringLiteral("抓包登录失败：%1").arg(e));emit captureSessionFailed(e);});
        connect(m_control,&TelnetClient::commandFinished,this,[this](const QString& command,const QString& output){if(m_refreshPending&&command==m_refreshCommand){m_refreshPending=false;applyInterfaceList(output);}});
        connect(m_control,&TelnetClient::errorOccurred,this,[this](const QString& e){if(m_pendingStart){m_pendingStart=false;emit captureSessionFailed(e);}m_state->setText(e);});
        connect(m_capture,&TelnetClient::errorOccurred,this,[this](const QString& e){if(m_pendingStart){m_pendingStart=false;emit captureSessionFailed(e);}m_state->setText(e);});
    }

    m_controller=new PacketCaptureController(m_control,m_capture,this);
    m_controller->setSingleSession(m_params.serialShared);
    connect(m_controller,&PacketCaptureController::captureStarting,this,[this](const QString& s){m_state->setText(s);});
    connect(m_controller,&PacketCaptureController::captureStarted,this,[this]{m_pendingStart=false;m_state->setText(QStringLiteral("正在实时抓包"));m_start->setEnabled(false);m_stop->setEnabled(true);emit captureSessionStarted();});
    connect(m_controller,&PacketCaptureController::captureStopped,this,[this]{m_state->setText(QStringLiteral("已停止"));m_start->setEnabled(true);m_stop->setEnabled(false);emit captureSessionStopped();});
    connect(m_controller,&PacketCaptureController::captureError,this,[this](const QString& e){m_pendingStart=false;m_state->setText(QStringLiteral("抓包失败：%1").arg(e));m_start->setEnabled(true);m_stop->setEnabled(false);emit captureSessionFailed(e);});
    connect(m_controller,&PacketCaptureController::packetReady,this,&CaptureSessionWidget::appendPacket);
    connect(m_controller,&PacketCaptureController::statsUpdated,this,&CaptureSessionWidget::updateStats);
    if(m_params.autoRefreshInterfaces)QTimer::singleShot(0,this,&CaptureSessionWidget::refreshInterfaces);
}

CaptureSessionWidget::~CaptureSessionWidget()=default;

void CaptureSessionWidget::buildUi(const QString& title)
{
    setWindowTitle(title);
    resize(1040,680);
    auto* root=new QVBoxLayout(this);
    auto* form=new QFormLayout;
    auto* ifaceRow=new QWidget(this);
    auto* ifaceLayout=new QHBoxLayout(ifaceRow);ifaceLayout->setContentsMargins(0,0,0,0);
    m_iface=new QComboBox(ifaceRow);m_iface->setEditable(true);m_iface->setInsertPolicy(QComboBox::NoInsert);m_iface->setObjectName(QStringLiteral("comboCaptureSessionInterface"));
    m_iface->lineEdit()->setPlaceholderText(QStringLiteral("下拉仅显示 ifconfig 实际接口（UP）；any=所有接口；也可手工输入 tun0 / usb0"));
    m_iface->addItem(QStringLiteral("any"));
    for(const QString& iface:m_params.interfaces)if(!iface.trimmed().isEmpty()&&m_iface->findText(iface)<0)m_iface->addItem(iface);
    m_refreshInterfaces=new QPushButton(QStringLiteral("刷新接口"),ifaceRow);
    ifaceLayout->addWidget(m_iface,1);ifaceLayout->addWidget(m_refreshInterfaces);
    m_filter=new QLineEdit(this);m_filter->setPlaceholderText(QStringLiteral("可留空抓全部流量，例如 port 2404 / host 192.168.1.10 / not port 22"));
    form->addRow(QStringLiteral("抓包接口"),ifaceRow);
    form->addRow(QStringLiteral("抓包过滤条件"),m_filter);
    root->addLayout(form);
    m_preview=new QLabel(this);m_preview->setTextInteractionFlags(Qt::TextSelectableByMouse);m_preview->setWordWrap(true);root->addWidget(m_preview);
    connect(m_iface,&QComboBox::editTextChanged,this,&CaptureSessionWidget::updatePreview);
    connect(m_refreshInterfaces,&QPushButton::clicked,this,&CaptureSessionWidget::refreshInterfaces);
    connect(m_filter,&QLineEdit::textChanged,this,&CaptureSessionWidget::updatePreview);

    auto* actions=new QHBoxLayout;
    m_start=new QPushButton(QStringLiteral("开始抓包"),this);
    m_stop=new QPushButton(QStringLiteral("停止抓包"),this);m_stop->setEnabled(false);
    m_export=new QPushButton(QStringLiteral("导出PCAP"),this);
    m_state=new QLabel(QStringLiteral("待机"),this);
    actions->addWidget(m_start);actions->addWidget(m_stop);actions->addWidget(m_export);actions->addSpacing(12);actions->addWidget(m_state,1);
    root->addLayout(actions);
    connect(m_start,&QPushButton::clicked,this,&CaptureSessionWidget::startCapture);
    connect(m_stop,&QPushButton::clicked,this,&CaptureSessionWidget::stopCapture);
    connect(m_export,&QPushButton::clicked,this,&CaptureSessionWidget::exportPcap);

    m_table=new QTableWidget(this);m_table->setColumnCount(7);
    m_table->setHorizontalHeaderLabels({QStringLiteral("No."),QStringLiteral("Time"),QStringLiteral("Source"),QStringLiteral("Destination"),QStringLiteral("Protocol"),QStringLiteral("Length"),QStringLiteral("Info")});
    m_table->horizontalHeader()->setSectionResizeMode(6,QHeaderView::Stretch);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);

    auto* workspace=new QSplitter(Qt::Vertical,this);
    workspace->setObjectName(QStringLiteral("captureSessionVerticalSplitter"));
    workspace->setHandleWidth(6);
    auto* bottom=new QSplitter(Qt::Horizontal,workspace);
    bottom->setObjectName(QStringLiteral("captureSessionBottomSplitter"));
    bottom->setHandleWidth(6);
    m_stats=new QPlainTextEdit(this);m_stats->setReadOnly(true);m_stats->setPlaceholderText(QStringLiteral("抓包统计"));
    m_detail=new QPlainTextEdit(this);m_detail->setReadOnly(true);m_detail->setPlaceholderText(QStringLiteral("选中/最新报文详情"));
    workspace->addWidget(m_table);
    bottom->addWidget(m_stats);
    bottom->addWidget(m_detail);
    workspace->addWidget(bottom);
    workspace->setStretchFactor(0,5);workspace->setStretchFactor(1,2);
    bottom->setStretchFactor(0,1);bottom->setStretchFactor(1,2);
    root->addWidget(workspace,1);

    QSettings settings(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));
    const QByteArray verticalState=settings.value(QStringLiteral("workspace/captureSessionVerticalSplitter")).toByteArray();
    const QByteArray bottomState=settings.value(QStringLiteral("workspace/captureSessionBottomSplitter")).toByteArray();
    if(verticalState.isEmpty()||!workspace->restoreState(verticalState))workspace->setSizes({470,190});
    if(bottomState.isEmpty()||!bottom->restoreState(bottomState))bottom->setSizes({280,620});
    connect(workspace,&QSplitter::splitterMoved,workspace,[workspace](int,int){QSettings s(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));s.setValue(QStringLiteral("workspace/captureSessionVerticalSplitter"),workspace->saveState());});
    connect(bottom,&QSplitter::splitterMoved,bottom,[bottom](int,int){QSettings s(QStringLiteral("FourFaith"),QStringLiteral("WanDiagTool"));s.setValue(QStringLiteral("workspace/captureSessionBottomSplitter"),bottom->saveState());});

    const QString keyBase=QStringLiteral("captureSession/%1").arg(title);
    new DetachablePanelManager(m_table,QStringLiteral("%1：报文列表").arg(title),keyBase+QStringLiteral("/packets"),this);
    new DetachablePanelManager(m_stats,QStringLiteral("%1：抓包统计").arg(title),keyBase+QStringLiteral("/stats"),this);
    new DetachablePanelManager(m_detail,QStringLiteral("%1：包详情").arg(title),keyBase+QStringLiteral("/detail"),this);
    updatePreview();
}

void CaptureSessionWidget::setCaptureSpec(const QString& iface,const QString& filter){m_iface->setEditText(iface);m_filter->setText(filter);}
QString CaptureSessionWidget::interfaceName() const{return m_iface?m_iface->currentText().trimmed():QString();}
QString CaptureSessionWidget::filterText() const{return m_filter?m_filter->text().trimmed():QString();}
bool CaptureSessionWidget::isRunning() const{return m_controller && m_controller->isRunning();}

void CaptureSessionWidget::updatePreview()
{
    if(!m_preview)return;
    const QString iface=interfaceName().isEmpty()?QStringLiteral("<接口>"):interfaceName();
    m_preview->setText(QStringLiteral("命令预览：%1").arg(PacketCaptureController::buildTextTcpdumpCommand(iface,filterText())));
}

void CaptureSessionWidget::refreshInterfaces()
{
    if(m_refreshPending)return;
    if(m_params.serialShared){
        if(!m_control || !m_control->isConnected()){m_state->setText(QStringLiteral("串口控制台未连接；仍可手动输入接口"));return;}
        if(m_control->isBusy()){m_state->setText(QStringLiteral("控制台正在执行命令，请稍后刷新接口"));return;}
        runInterfaceRefresh();
        return;
    }
    if(m_controlLogged){runInterfaceRefresh();return;}
    m_refreshPending=true;
    m_state->setText(QStringLiteral("正在连接路由器并读取全部接口..."));
    if(!m_control->isConnected())m_control->connectToHost(m_params.host,m_params.port);
    else m_control->login(m_params.user,m_params.password);
}

void CaptureSessionWidget::runInterfaceRefresh()
{
    if(!m_control || !m_control->isConnected() || m_control->isBusy())return;
    m_refreshCommand=QStringLiteral("ifconfig 2>/dev/null");
    m_refreshPending=true;
    if(m_refreshInterfaces)m_refreshInterfaces->setEnabled(false);
    m_state->setText(QStringLiteral("正在刷新抓包接口..."));
    m_control->executeCommand(m_refreshCommand,5000);
}

void CaptureSessionWidget::applyInterfaceList(const QString& output)
{
    if(m_refreshInterfaces)m_refreshInterfaces->setEnabled(true);
    const QString current=interfaceName();
    const QList<DeviceInterfaceInfo> infos=DeviceDiscoveryParser::parseInterfaces(output);
    QStringList names;
    names<<QStringLiteral("any");
    for(const auto& info:infos)if(info.up && !info.name.isEmpty()&&!names.contains(info.name))names<<info.name;
    m_iface->blockSignals(true);m_iface->clear();m_iface->addItems(names);if(!current.isEmpty())m_iface->setEditText(current);m_iface->blockSignals(false);
    updatePreview();
    const int realCount=qMax(0,names.size()-1); // exclude tcpdump pseudo-interface `any`
    m_state->setText(realCount==0?QStringLiteral("ifconfig 未返回 UP 接口；仍可选择 any 或手工输入"):QStringLiteral("已读取 %1 个 ifconfig UP 接口；any=所有接口").arg(realCount));
}

void CaptureSessionWidget::startCapture()
{
    if(isRunning()||m_pendingStart)return;
    if(interfaceName().isEmpty()){m_state->setText(QStringLiteral("请输入抓包接口"));return;}
    if(m_startGuard){const QString reason=m_startGuard();if(!reason.isEmpty()){m_state->setText(reason);QMessageBox::warning(this,QStringLiteral("无法启动抓包"),reason);return;}}
    m_no=0;m_table->setRowCount(0);m_stats->clear();m_detail->clear();
    m_pendingStart=true;
    if(m_params.serialShared){
        if(!m_control || !m_control->isConnected()){m_pendingStart=false;m_state->setText(QStringLiteral("串口控制台未连接"));return;}
        m_controlLogged=m_captureLogged=true;
        tryStartController();
    }else ensureNetworkLoggedIn();
}

void CaptureSessionWidget::ensureNetworkLoggedIn()
{
    if(m_controlLogged && m_captureLogged){tryStartController();return;}
    m_state->setText(QStringLiteral("正在建立独立抓包Telnet会话..."));
    if(!m_control->isConnected())m_control->connectToHost(m_params.host,m_params.port);
    else if(!m_controlLogged)m_control->login(m_params.user,m_params.password);
    if(!m_capture->isConnected())m_capture->connectToHost(m_params.host,m_params.port);
    else if(!m_captureLogged)m_capture->login(m_params.user,m_params.password);
}

void CaptureSessionWidget::tryStartController()
{
    if(!m_pendingStart || !m_controlLogged || !m_captureLogged)return;
    m_state->setText(QStringLiteral("正在启动 tcpdump..."));
    m_controller->start(interfaceName(),filterText());
}

void CaptureSessionWidget::stopCapture(){if(m_controller)m_controller->stop();}

void CaptureSessionWidget::appendPacket(const ParsedPacket& p)
{
    if(!p.valid)return;
    constexpr int MaxVisiblePackets=20000;
    if(m_table->rowCount()>=MaxVisiblePackets)m_table->removeRow(0);
    const int row=m_table->rowCount();m_table->insertRow(row);++m_no;
    const QString time=p.timestamp.isValid()?p.timestamp.toString(QStringLiteral("HH:mm:ss.zzz")):QStringLiteral("--");
    const QString src=p.sourcePort?QStringLiteral("%1:%2").arg(p.sourceIp).arg(p.sourcePort):p.sourceIp;
    const QString dst=p.destinationPort?QStringLiteral("%1:%2").arg(p.destinationIp).arg(p.destinationPort):p.destinationIp;
    const QStringList values={QString::number(m_no),time,src,dst,p.protocol,QString::number(p.capturedLength),p.summary};
    for(int c=0;c<values.size();++c)m_table->setItem(row,c,new QTableWidgetItem(values[c]));
    m_table->scrollToBottom();
    m_detail->setPlainText(QStringLiteral("%1 -> %2\n协议：%3\nTCP Payload：%4 Bytes\nHEX：%5")
        .arg(src,dst,p.protocol).arg(p.tcpPayloadLength).arg(QString::fromLatin1(p.payload.toHex(' '))));
    emit packetObserved(p);
}

void CaptureSessionWidget::updateStats(const CaptureStats& s)
{
    m_stats->setPlainText(QStringLiteral("总包数：%1\nTCP：%2  UDP：%3  ICMP：%4\nSYN：%5  RST：%6  FIN：%7\nPayload/重传观察：%8")
        .arg(s.totalPackets).arg(s.tcpPackets).arg(s.udpPackets).arg(s.icmpPackets).arg(s.tcpSyn).arg(s.tcpRst).arg(s.tcpFin).arg(s.suspectedRetransmissions));
}

void CaptureSessionWidget::exportPcap()
{
    const QString path=QFileDialog::getSaveFileName(this,QStringLiteral("导出抓包"),QStringLiteral("capture_%1.pcap").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),QStringLiteral("PCAP (*.pcap)"));
    if(path.isEmpty())return;
    QString error;
    if(!m_controller->exportBufferedPcap(path,&error))QMessageBox::warning(this,QStringLiteral("导出失败"),error);
    else m_state->setText(QStringLiteral("PCAP已保存：%1").arg(path));
}

void CaptureSessionWidget::closeEvent(QCloseEvent* event)
{
    emit captureSessionClosing();
    if(isRunning())m_controller->stop();
    event->accept();
}
