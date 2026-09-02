#include "RemoteToolDialog.h"
#include "diagnostic/ConnectivityProbe.h"
#include "diagnostic/LogAnalyzer.h"
#include "telnet/TelnetClient.h"
#include "ui/DetachablePanelManager.h"

#include <QCheckBox>
#include <QAbstractItemView>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QTableWidget>
#include <QHeaderView>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QList>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardPaths>
#include <QTimer>
#include <QScrollBar>
#include <QTextCursor>
#include <QTextDocument>
#include <QTime>
#include <utility>
#include <QUrl>
#include <QVBoxLayout>

namespace {
constexpr int CommandRole=Qt::UserRole;
constexpr int BuiltinRole=Qt::UserRole+1;
constexpr int NoteRole=Qt::UserRole+2;
constexpr int CategoryRole=Qt::UserRole+3;

QString settingsApplicationName()
{
    const QString appName=QCoreApplication::applicationName();
    return appName.startsWith(QStringLiteral("test_"),Qt::CaseInsensitive)
        ?QStringLiteral("WanDiagToolTests"):QStringLiteral("WanDiagTool");
}

void addCommandItem(QComboBox* combo,const QString& name,const QString& command,bool builtin,const QString& note=QString(),const QString& category=QStringLiteral("自定义"))
{
    if(!combo)return;
    combo->addItem(name,command);
    const int index=combo->count()-1;
    combo->setItemData(index,builtin,BuiltinRole);
    combo->setItemData(index,note,NoteRole);
    combo->setItemData(index,category.trimmed().isEmpty()?QStringLiteral("自定义"):category.trimmed(),CategoryRole);
    combo->setItemData(index,command,Qt::ToolTipRole);
}

bool editQuickCommandDialog(QWidget* parent,const QString& title,QString& name,QString& command,QString& note,QString& category)
{
    QDialog dialog(parent);dialog.setWindowTitle(title);dialog.resize(650,250);
    auto* root=new QVBoxLayout(&dialog);auto* form=new QFormLayout;
    auto* nameEdit=new QLineEdit(name,&dialog);auto* commandEdit=new QLineEdit(command,&dialog);auto* noteEdit=new QLineEdit(note,&dialog);
    auto* categoryEdit=new QComboBox(&dialog);categoryEdit->setEditable(true);categoryEdit->addItems({QStringLiteral("只读检查"),QStringLiteral("抓包分析"),QStringLiteral("日志"),QStringLiteral("维护操作"),QStringLiteral("自定义")});categoryEdit->setCurrentText(category.isEmpty()?QStringLiteral("自定义"):category);
    nameEdit->setObjectName(QStringLiteral("editQuickCommandName"));commandEdit->setObjectName(QStringLiteral("editQuickCommandValue"));noteEdit->setObjectName(QStringLiteral("editQuickCommandNote"));categoryEdit->setObjectName(QStringLiteral("comboQuickCommandCategory"));
    commandEdit->setPlaceholderText(QStringLiteral("例如：nvram get wan_ipaddr"));noteEdit->setPlaceholderText(QStringLiteral("可选：说明这条命令做什么"));
    form->addRow(QStringLiteral("分类"),categoryEdit);form->addRow(QStringLiteral("名称"),nameEdit);form->addRow(QStringLiteral("命令"),commandEdit);form->addRow(QStringLiteral("备注"),noteEdit);root->addLayout(form);
    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,&dialog);root->addWidget(buttons);
    QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);QObject::connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    if(dialog.exec()!=QDialog::Accepted)return false;
    name=nameEdit->text().trimmed();command=commandEdit->text().trimmed();note=noteEdit->text().trimmed();category=categoryEdit->currentText().trimmed();if(category.isEmpty())category=QStringLiteral("自定义");
    if(name.isEmpty()||command.isEmpty()){QMessageBox::warning(parent,QStringLiteral("内容不完整"),QStringLiteral("名称和命令不能为空。"));return false;}
    return true;
}

}

RemoteToolDialog::RemoteToolDialog(Mode mode,const RemoteConnectionParams& params,const QString& initialTarget,QWidget* parent)
    :QDialog(parent),m_mode(mode),m_params(params),m_client(new TelnetClient(this)),m_logFile(new QFile(this))
{
    setAttribute(Qt::WA_DeleteOnClose,true);
    buildUi(initialTarget);
    connect(m_client,&TelnetClient::connected,this,[this]{
        m_status->setText(QStringLiteral("TCP已连接，正在登录..."));
        m_waitingLogin=true;
        m_client->login(m_params.user,m_params.password);
    });
    connect(m_client,&TelnetClient::loginSucceeded,this,[this]{
        m_waitingLogin=false;
        m_status->setText(QStringLiteral("已登录 %1").arg(m_params.host));
        runPendingAction();
    });
    connect(m_client,&TelnetClient::loginFailed,this,[this](const QString& reason){
        m_waitingLogin=false;m_actionPending=false;
        m_status->setText(QStringLiteral("登录失败"));appendText(reason);
        closeModuleLogFile();
        if(m_start)m_start->setEnabled(true);
    });
    connect(m_client,&TelnetClient::errorOccurred,this,[this](const QString& reason){
        m_actionPending=false;m_waitingLogin=false;
        appendText(QStringLiteral("[连接错误] ")+reason);
        closeModuleLogFile();
        if(m_start)m_start->setEnabled(true);
    });
    connect(m_client,&TelnetClient::visibleTextReceived,this,[this](const QString& text){
        if(m_mode==Mode::ModuleLog){
            if(m_moduleLogSetupState==ModuleLogSetupState::Tailing)queueModuleLogText(text);
            return; // login/setup transcript is represented by the status labels, not mixed into system log content
        }
        appendText(text);
    });
    connect(m_client,&TelnetClient::commandFinished,this,[this](const QString& command,const QString& output){
        if(m_mode==Mode::ModuleLog){
            auto outputHasScalar=[](const QString& value,const QString& expected){
                const QStringList lines=value.split(QRegularExpression(QStringLiteral("[\r\n]+")),Qt::SkipEmptyParts);
                for(const QString& line:lines)if(line.trimmed()==expected)return true;
                return false;
            };
            if(m_moduleLogSetupState==ModuleLogSetupState::CheckingDebug && command==QStringLiteral("nvram get debuglog_enable")){
                if(outputHasScalar(output,QStringLiteral("1"))){
                    m_moduleLogSetupState=ModuleLogSetupState::CheckingSyslog;
                    m_status->setText(QStringLiteral("正在检查 syslogd_enable..."));
                    m_client->executeCommand(QStringLiteral("nvram get syslogd_enable"),3000);
                }else{
                    m_moduleLogSetupState=ModuleLogSetupState::SettingDebug;
                    m_status->setText(QStringLiteral("正在开启 debuglog_enable=1..."));
                    m_client->executeCommand(QStringLiteral("nvram set debuglog_enable=1"),3000);
                }
                return;
            }
            if(m_moduleLogSetupState==ModuleLogSetupState::SettingDebug && command==QStringLiteral("nvram set debuglog_enable=1")){
                m_moduleLogSetupState=ModuleLogSetupState::CommitDebug;
                m_status->setText(QStringLiteral("正在保存系统日志开关..."));
                m_client->executeCommand(QStringLiteral("nvram commit"),5000);
                return;
            }
            if(m_moduleLogSetupState==ModuleLogSetupState::CommitDebug && command==QStringLiteral("nvram commit")){
                m_moduleLogSetupState=ModuleLogSetupState::CheckingSyslog;
                m_status->setText(QStringLiteral("正在检查 syslogd_enable..."));
                m_client->executeCommand(QStringLiteral("nvram get syslogd_enable"),3000);
                return;
            }
            if(m_moduleLogSetupState==ModuleLogSetupState::CheckingSyslog && command==QStringLiteral("nvram get syslogd_enable")){
                if(outputHasScalar(output,QStringLiteral("3"))){
                    beginModuleLogTail();
                }else{
                    m_moduleLogSetupState=ModuleLogSetupState::SettingSyslog;
                    m_status->setText(QStringLiteral("正在设置 syslogd_enable=3..."));
                    m_client->executeCommand(QStringLiteral("nvram set syslogd_enable=3"),3000);
                }
                return;
            }
            if(m_moduleLogSetupState==ModuleLogSetupState::SettingSyslog && command==QStringLiteral("nvram set syslogd_enable=3")){
                m_moduleLogSetupState=ModuleLogSetupState::CommitSyslog;
                m_status->setText(QStringLiteral("正在保存日志输出配置..."));
                m_client->executeCommand(QStringLiteral("nvram commit"),5000);
                return;
            }
            if(m_moduleLogSetupState==ModuleLogSetupState::CommitSyslog && command==QStringLiteral("nvram commit")){
                beginModuleLogTail();
            }
            return;
        }
        m_actionPending=false;
        if(m_start)m_start->setEnabled(true);
        if(m_mode==Mode::Ping){
            const PingResult ping=ConnectivityProbe::parsePingOutput(output);
            QString summary;
            if(ping.transmitted>=0 && ping.received>=0){
                summary=QStringLiteral("Ping完成：接收 %1/%2").arg(ping.received).arg(ping.transmitted);
                if(ping.packetLossPercent>=0)summary+=QStringLiteral("，丢包 %1%").arg(ping.packetLossPercent);
                if(ping.avgRttMs>=0)summary+=QStringLiteral("，平均 %1 ms").arg(ping.avgRttMs,0,'f',1);
            }else if(ping.reachable){
                summary=QStringLiteral("Ping完成：已收到目标应答");
            }else{
                summary=QStringLiteral("Ping完成：未收到目标应答");
            }
            if(!ping.failureReason.isEmpty())summary+=QStringLiteral(" | %1").arg(ping.failureReason);
            m_status->setText(summary);
        }else{
            m_status->setText(QStringLiteral("命令完成"));
        }
    });
}

RemoteToolDialog::~RemoteToolDialog()
{
    if(m_moduleLogRefreshTimer)m_moduleLogRefreshTimer->stop();
    if(m_moduleLogIdleTimer)m_moduleLogIdleTimer->stop();
    flushPendingModuleLog();
    closeModuleLogFile();
}

bool RemoteToolDialog::commandNeedsConfirmation(const QString& command)
{
    const QString value=command.trimmed().toLower();
    if(value.isEmpty())return false;
    static const QList<QRegularExpression> patterns={
        QRegularExpression(QStringLiteral(R"(\bnvram\s+(set|commit|unset)\b)")),
        QRegularExpression(QStringLiteral(R"((^|[;&|]\s*|\s)(reboot|halt|poweroff)(\s|$))")),
        QRegularExpression(QStringLiteral(R"((^|[;&|]\s*|\s)rm(\s|$))")),
        QRegularExpression(QStringLiteral(R"(\b(mtd|flash_erase|flashcp|dd)\b)")),
        QRegularExpression(QStringLiteral(R"(\biptables\s+(-f|--flush)\b)")),
        QRegularExpression(QStringLiteral(R"(\b(kill|killall|pkill)\b)"))
    };
    for(const auto& pattern:patterns)
        if(pattern.match(value).hasMatch())return true;
    return false;
}

void RemoteToolDialog::buildUi(const QString& initialTarget)
{
    QString title;
    if(m_mode==Mode::Ping) title=QStringLiteral("Ping 工具");
    else if(m_mode==Mode::Command) title=QStringLiteral("命令 / 快捷指令");
    else title=QStringLiteral("模块实时日志");
    setWindowTitle(title+QStringLiteral(" - ")+m_params.host);
    resize(760,500);
    setMinimumSize(620,420);

    setStyleSheet(QStringLiteral(R"QSS(
QDialog { background:#f4f7fa; color:#26384a; font-family:"Microsoft YaHei UI"; font-size:10pt; }
QLineEdit,QSpinBox,QComboBox { min-height:31px; background:#fff; border:1px solid #bdcad6; border-radius:6px; padding:0 8px; }
QComboBox QAbstractItemView { background:#fff; color:#29445d; border:1px solid #9bb8cc; border-radius:5px; outline:0; selection-background-color:#dcecf8; selection-color:#17324a; }
QComboBox QAbstractItemView::item { min-height:28px; padding:3px 8px; background:#fff; }
QComboBox QAbstractItemView::item:hover,QComboBox QAbstractItemView::item:selected { background:#dcecf8; color:#17324a; }
QPushButton { min-height:31px; padding:0 14px; background:#fff; color:#29445d; border:1px solid #b9c7d4; border-radius:6px; font-weight:600; }
QPushButton:hover { background:#edf4fa; border-color:#7ea5c6; }
QPushButton#btnRemoteStart { background:#24679b; color:#fff; border-color:#24679b; }
QPlainTextEdit { background:#fbfcfd; border:1px solid #d7e0e8; border-radius:6px; padding:7px; }
QLabel#labelRemoteStatus { color:#1c5f8f; font-weight:700; }
QLabel#labelModuleLogPath { color:#687b8d; font-size:9pt; }
)QSS"));

    auto* root=new QVBoxLayout(this);
    root->setContentsMargins(14,14,14,14);
    root->setSpacing(10);
    m_status=new QLabel(QStringLiteral("未连接"),this);
    m_status->setObjectName(QStringLiteral("labelRemoteStatus"));
    root->addWidget(m_status);

    auto* form=new QFormLayout;
    form->setHorizontalSpacing(10);
    form->setVerticalSpacing(8);
    if(m_mode==Mode::Ping){
        m_target=new QLineEdit(initialTarget.isEmpty()?QStringLiteral("223.5.5.5"):initialTarget,this);
        m_target->setObjectName(QStringLiteral("editRemotePingTarget"));
        m_count=new QSpinBox(this);m_count->setObjectName(QStringLiteral("spinRemotePingCount"));m_count->setRange(1,20);m_count->setValue(10);
        form->addRow(QStringLiteral("目标地址"),m_target);
        form->addRow(QStringLiteral("次数"),m_count);
    }else if(m_mode==Mode::Command){
        // m_command remains the compact data model so existing settings/tests stay compatible.
        m_command=new QComboBox(this);
        m_command->setObjectName(QStringLiteral("comboRemoteCommand"));
        m_command->hide();
        loadQuickCommands();

        auto* quickHint=new QLabel(QStringLiteral("快捷指令：支持分类筛选和搜索；单击填入执行命令，双击直接执行。导入项始终作为自定义副本。"),this);
        quickHint->setWordWrap(true);root->addWidget(quickHint);
        auto* commandFilterRow=new QHBoxLayout;
        m_commandCategoryFilter=new QComboBox(this);m_commandCategoryFilter->setObjectName(QStringLiteral("comboQuickCommandCategoryFilter"));m_commandCategoryFilter->addItem(QStringLiteral("全部分类"));
        m_commandSearch=new QLineEdit(this);m_commandSearch->setObjectName(QStringLiteral("editQuickCommandSearch"));m_commandSearch->setPlaceholderText(QStringLiteral("快捷命令搜索（搜索名称 / 命令 / 备注）"));
        commandFilterRow->addWidget(new QLabel(QStringLiteral("分类"),this));commandFilterRow->addWidget(m_commandCategoryFilter);commandFilterRow->addWidget(m_commandSearch,1);root->addLayout(commandFilterRow);
        m_commandTable=new QTableWidget(this);
        m_commandTable->setObjectName(QStringLiteral("tableQuickCommands"));
        m_commandTable->setColumnCount(4);
        m_commandTable->setHorizontalHeaderLabels({QStringLiteral("分类"),QStringLiteral("名称"),QStringLiteral("命令"),QStringLiteral("备注")});
        m_commandTable->horizontalHeader()->setSectionResizeMode(0,QHeaderView::ResizeToContents);
        m_commandTable->horizontalHeader()->setSectionResizeMode(1,QHeaderView::ResizeToContents);
        m_commandTable->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Stretch);
        m_commandTable->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);
        m_commandTable->verticalHeader()->setVisible(false);
        m_commandTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_commandTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_commandTable->setAlternatingRowColors(true);
        m_commandTable->setMinimumHeight(120);
        rebuildQuickCommandTable();

        m_commandText=new QLineEdit(this);
        m_commandText->setObjectName(QStringLiteral("editRemoteCommandText"));
        m_commandText->setPlaceholderText(QStringLiteral("选择快捷指令会自动填入，也可以手工输入临时命令"));
        form->addRow(QStringLiteral("执行命令"),m_commandText);
        connect(m_command,qOverload<int>(&QComboBox::currentIndexChanged),this,[this](int){syncCommandFromSelection();});
        connect(m_commandTable,&QTableWidget::cellClicked,this,[this](int row,int){commandQuickCommandSelected(row);});
        connect(m_commandTable,&QTableWidget::cellDoubleClicked,this,[this](int row,int){commandQuickCommandSelected(row);ensureConnectedAndRun();});
        auto applyQuickFilter=[this]{
            if(!m_commandTable||!m_command)return;
            const QString category=m_commandCategoryFilter?m_commandCategoryFilter->currentText():QStringLiteral("全部分类");
            const QString query=m_commandSearch?m_commandSearch->text().trimmed():QString();
            for(int row=0;row<m_command->count();++row){
                const QString cat=m_command->itemData(row,CategoryRole).toString();
                const QString hay=(m_command->itemText(row)+QLatin1Char(' ')+m_command->itemData(row,CommandRole).toString()+QLatin1Char(' ')+m_command->itemData(row,NoteRole).toString());
                const bool categoryOk=category==QStringLiteral("全部分类")||cat==category;
                const bool textOk=query.isEmpty()||hay.contains(query,Qt::CaseInsensitive);
                m_commandTable->setRowHidden(row,!(categoryOk&&textOk));
            }
        };
        connect(m_commandCategoryFilter,qOverload<int>(&QComboBox::currentIndexChanged),this,[applyQuickFilter](int){applyQuickFilter();});
        connect(m_commandSearch,&QLineEdit::textChanged,this,[applyQuickFilter](const QString&){applyQuickFilter();});
        if(m_commandTable->rowCount()>0){m_commandTable->selectRow(0);commandQuickCommandSelected(0);}
    }
    if(form->rowCount()>0) root->addLayout(form);

    if(m_mode==Mode::Command){
        auto* quickButtons=new QHBoxLayout;
        m_commandAdd=new QPushButton(QStringLiteral("新增快捷指令"),this);m_commandAdd->setObjectName(QStringLiteral("btnCommandAdd"));
        m_commandEdit=new QPushButton(QStringLiteral("编辑"),this);m_commandEdit->setObjectName(QStringLiteral("btnCommandEdit"));
        m_commandDelete=new QPushButton(QStringLiteral("删除"),this);m_commandDelete->setObjectName(QStringLiteral("btnCommandDelete"));
        m_commandImport=new QPushButton(QStringLiteral("导入"),this);m_commandImport->setObjectName(QStringLiteral("btnCommandImport"));
        m_commandExport=new QPushButton(QStringLiteral("导出全部"),this);m_commandExport->setObjectName(QStringLiteral("btnCommandExport"));
        quickButtons->addWidget(m_commandAdd);quickButtons->addWidget(m_commandEdit);quickButtons->addWidget(m_commandDelete);
        quickButtons->addSpacing(10);quickButtons->addWidget(m_commandImport);quickButtons->addWidget(m_commandExport);quickButtons->addStretch();
        root->addLayout(quickButtons);
        connect(m_commandAdd,&QPushButton::clicked,this,&RemoteToolDialog::addQuickCommand);
        connect(m_commandEdit,&QPushButton::clicked,this,&RemoteToolDialog::editQuickCommand);
        connect(m_commandDelete,&QPushButton::clicked,this,&RemoteToolDialog::deleteQuickCommand);
        connect(m_commandImport,&QPushButton::clicked,this,&RemoteToolDialog::importQuickCommands);
        connect(m_commandExport,&QPushButton::clicked,this,&RemoteToolDialog::exportQuickCommands);
        syncCommandFromSelection();
    }

    if(m_mode==Mode::ModuleLog){
        auto* logTools=new QHBoxLayout;
        QSettings settings(QStringLiteral("FourFaith"),settingsApplicationName());
        m_autoSaveLog=new QCheckBox(QStringLiteral("自动保存日志"),this);
        m_autoSaveLog->setObjectName(QStringLiteral("checkModuleLogAutoSave"));
        m_autoSaveLog->setChecked(settings.value(QStringLiteral("moduleLog/autoSave"),true).toBool());
        m_openLogFolder=new QPushButton(QStringLiteral("打开日志目录"),this);m_openLogFolder->setObjectName(QStringLiteral("btnOpenModuleLogFolder"));
        m_saveLogAs=new QPushButton(QStringLiteral("另存为"),this);m_saveLogAs->setObjectName(QStringLiteral("btnSaveModuleLogAs"));
        logTools->addWidget(m_autoSaveLog);logTools->addWidget(m_openLogFolder);logTools->addWidget(m_saveLogAs);logTools->addStretch();
        root->addLayout(logTools);
        m_logPathLabel=new QLabel(QStringLiteral("默认保存：%1").arg(QDir::toNativeSeparators(moduleLogDirectory())),this);
        m_logPathLabel->setObjectName(QStringLiteral("labelModuleLogPath"));
        m_logPathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        root->addWidget(m_logPathLabel);
        m_moduleLogRuntime=new QLabel(QStringLiteral("模块日志实时读取：未启动 | 命令：tail /tmp/.systemlog -f | 已接收：0 行"),this);
        m_moduleLogRuntime->setObjectName(QStringLiteral("labelModuleLogRuntime"));
        m_moduleLogRuntime->setWordWrap(true);
        m_moduleLogRuntime->setStyleSheet(QStringLiteral("QLabel{color:#1c5f8f;background:#f5f9fc;border:1px solid #d4e0ea;border-radius:6px;padding:7px;}"));
        root->addWidget(m_moduleLogRuntime);
        m_moduleLogRefreshTimer=new QTimer(this);
        m_moduleLogRefreshTimer->setInterval(50);
        connect(m_moduleLogRefreshTimer,&QTimer::timeout,this,&RemoteToolDialog::flushPendingModuleLog);
        m_moduleLogIdleTimer=new QTimer(this);
        m_moduleLogIdleTimer->setSingleShot(true);
        m_moduleLogIdleTimer->setInterval(10000);
        connect(m_moduleLogIdleTimer,&QTimer::timeout,this,[this]{
            if(m_moduleLogSetupState==ModuleLogSetupState::Tailing){
                m_status->setText(QStringLiteral("已连接，当前暂无新日志"));
                updateModuleLogRuntimeLabel();
            }
        });
        m_moduleLiveSummary=new QLabel(QStringLiteral("实时提取：模组 -- | SIM -- | 注册 -- | RSRP -- | SINR -- | WAN --"),this);
        m_moduleLiveSummary->setObjectName(QStringLiteral("labelModuleLiveSummary"));
        m_moduleLiveSummary->setWordWrap(true);
        m_moduleLiveSummary->setStyleSheet(QStringLiteral("QLabel{background:#eef5fb;border:1px solid #cbd9e6;border-radius:6px;padding:8px;color:#29445d;font-weight:600;}"));
        root->addWidget(m_moduleLiveSummary);
        connect(m_autoSaveLog,&QCheckBox::toggled,this,[this](bool checked){
            QSettings settings(QStringLiteral("FourFaith"),settingsApplicationName());
            settings.setValue(QStringLiteral("moduleLog/autoSave"),checked);
            if(checked && m_actionPending && !m_logFile->isOpen())prepareModuleLogFile();
            if(!checked)closeModuleLogFile();
        });
        connect(m_openLogFolder,&QPushButton::clicked,this,&RemoteToolDialog::openModuleLogFolder);
        connect(m_saveLogAs,&QPushButton::clicked,this,&RemoteToolDialog::saveModuleLogAs);
    }

    auto* buttons=new QHBoxLayout;
    m_start=new QPushButton(m_mode==Mode::ModuleLog?QStringLiteral("开始查看"):m_mode==Mode::Command?QStringLiteral("执行当前命令"):QStringLiteral("执行"),this);
    m_start->setObjectName(QStringLiteral("btnRemoteStart"));
    m_stop=new QPushButton(QStringLiteral("停止 / 断开"),this);
    m_stop->setObjectName(QStringLiteral("btnRemoteStop"));
    buttons->addWidget(m_start);buttons->addWidget(m_stop);buttons->addStretch();
    root->addLayout(buttons);

    m_output=new QPlainTextEdit(this);m_output->setObjectName(QStringLiteral("txtRemoteOutput"));m_output->setReadOnly(true);
    m_output->document()->setMaximumBlockCount(5000);
    if(m_mode==Mode::Command && m_commandTable){
        auto* workspace=new QSplitter(Qt::Vertical,this);
        workspace->setObjectName(QStringLiteral("remoteCommandWorkspaceSplitter"));
        workspace->setHandleWidth(6);
        workspace->addWidget(m_commandTable);
        workspace->addWidget(m_output);
        workspace->setStretchFactor(0,2);workspace->setStretchFactor(1,3);
        root->addWidget(workspace,1);
        QSettings settings(QStringLiteral("FourFaith"),settingsApplicationName());
        const QByteArray state=settings.value(QStringLiteral("workspace/commandSplitter")).toByteArray();
        if(state.isEmpty()||!workspace->restoreState(state))workspace->setSizes({230,300});
        connect(workspace,&QSplitter::splitterMoved,workspace,[workspace](int,int){QSettings s(QStringLiteral("FourFaith"),settingsApplicationName());s.setValue(QStringLiteral("workspace/commandSplitter"),workspace->saveState());});
        new DetachablePanelManager(m_commandTable,QStringLiteral("快捷命令列表"),QStringLiteral("remoteCommandList"),this);
        new DetachablePanelManager(m_output,QStringLiteral("命令实时输出"),QStringLiteral("remoteCommandOutput"),this);
    }else{
        root->addWidget(m_output,1);
        const QString panelTitle=m_mode==Mode::Ping?QStringLiteral("Ping 输出"):QStringLiteral("实时系统日志输出");
        const QString panelKey=m_mode==Mode::Ping?QStringLiteral("remotePingOutput"):QStringLiteral("remoteModuleLogOutput");
        new DetachablePanelManager(m_output,panelTitle,panelKey,this);
    }

    connect(m_start,&QPushButton::clicked,this,[this]{ensureConnectedAndRun();});
    connect(m_stop,&QPushButton::clicked,this,[this]{
        m_actionPending=false;m_waitingLogin=false;m_moduleLogSetupState=ModuleLogSetupState::Idle;
        if(m_moduleLogRefreshTimer)m_moduleLogRefreshTimer->stop();
        if(m_moduleLogIdleTimer)m_moduleLogIdleTimer->stop();
        flushPendingModuleLog();
        m_client->disconnectFromHost();
        closeModuleLogFile();
        m_status->setText(QStringLiteral("已断开"));m_start->setEnabled(true);
        updateModuleLogRuntimeLabel();
    });
}

void RemoteToolDialog::ensureConnectedAndRun()
{
    if(m_actionPending || m_waitingLogin) return;
    if(m_mode==Mode::Ping && (!m_target || ConnectivityProbe::buildPingCommand(m_target->text().trimmed(),m_count->value()).isEmpty())){
        appendText(QStringLiteral("[错误] 目标IPv4地址或Ping次数无效"));return;
    }
    if(m_mode==Mode::Command){
        const QString command=m_commandText?m_commandText->text().trimmed():QString();
        if(command.isEmpty()){appendText(QStringLiteral("[错误] 命令为空"));return;}
        if(commandNeedsConfirmation(command)){
            const auto answer=QMessageBox::warning(this,QStringLiteral("确认危险命令"),
                QStringLiteral("该命令可能修改设备配置、重启设备或删除数据：\n\n%1\n\n是否仍要执行？").arg(command),
                QMessageBox::Yes|QMessageBox::No,QMessageBox::No);
            if(answer!=QMessageBox::Yes){appendText(QStringLiteral("[已取消] 危险命令未执行"));return;}
        }
    }
    if(m_mode==Mode::ModuleLog && m_autoSaveLog && m_autoSaveLog->isChecked() && !m_logFile->isOpen()){
        if(!prepareModuleLogFile())appendText(QStringLiteral("[提示] 自动保存文件创建失败，本次仍可继续查看日志"));
    }
    m_actionPending=true;m_start->setEnabled(false);
    if(!m_client->isConnected()){
        m_status->setText(QStringLiteral("正在连接 %1:%2...").arg(m_params.host).arg(m_params.port));
        m_client->connectToHost(m_params.host,m_params.port);
        return;
    }
    runPendingAction();
}

void RemoteToolDialog::runPendingAction()
{
    if(!m_actionPending || !m_client->isConnected()) return;
    if(m_mode==Mode::Ping){
        const QString cmd=ConnectivityProbe::buildPingCommand(m_target->text().trimmed(),m_count->value());
        m_status->setText(QStringLiteral("正在Ping %1").arg(m_target->text().trimmed()));
        m_client->executeCommand(cmd,4000+m_count->value()*1800);
    }else if(m_mode==Mode::Command){
        const QString cmd=m_commandText->text().trimmed();
        m_status->setText(QStringLiteral("执行: %1").arg(cmd));
        m_client->executeCommand(cmd,12000);
    }else{
        m_moduleLogSetupState=ModuleLogSetupState::CheckingDebug;
        m_status->setText(QStringLiteral("正在检查系统日志开关..."));
        m_client->executeCommand(QStringLiteral("nvram get debuglog_enable"),3000);
    }
}

void RemoteToolDialog::appendText(const QString& text)
{
    if(!m_output || text.isEmpty())return;
    // Telnet readyRead chunks are stream fragments, not logical lines. Preserve bytes/text exactly;
    // adding a newline after every chunk was the reason commands/log lines could appear as "t\nail ...".
    const bool follow=m_output->verticalScrollBar()->value()>=m_output->verticalScrollBar()->maximum()-2;
    m_output->moveCursor(QTextCursor::End);
    m_output->insertPlainText(text);
    if(follow)m_output->verticalScrollBar()->setValue(m_output->verticalScrollBar()->maximum());
}

void RemoteToolDialog::beginModuleLogTail()
{
    if(m_mode!=Mode::ModuleLog)return;
    m_moduleLogSetupState=ModuleLogSetupState::Tailing;
    m_pendingModuleLogText.clear();
    m_moduleLogBuffer.clear();
    m_moduleLogLineCount=0;
    m_lastModuleLogDataTime.clear();
    if(m_output)m_output->clear();
    m_status->setText(QStringLiteral("模块日志实时读取"));
    updateModuleLogRuntimeLabel();
    if(m_moduleLogRefreshTimer)m_moduleLogRefreshTimer->start();
    if(m_moduleLogIdleTimer)m_moduleLogIdleTimer->start();
    m_client->executeCommand(QStringLiteral("tail /tmp/.systemlog -f"),24*60*60*1000);
}

void RemoteToolDialog::queueModuleLogText(const QString& text)
{
    if(m_mode!=Mode::ModuleLog || text.isEmpty())return;
    m_pendingModuleLogText+=text;
    m_moduleLogBuffer+=text;
    constexpr int MaxModuleLogChars=512*1024;
    if(m_moduleLogBuffer.size()>MaxModuleLogChars)m_moduleLogBuffer.remove(0,m_moduleLogBuffer.size()-MaxModuleLogChars);
    m_moduleLogLineCount+=text.count(QLatin1Char('\n'));
    m_lastModuleLogDataTime=QTime::currentTime().toString(QStringLiteral("HH:mm:ss"));
    m_status->setText(QStringLiteral("模块日志实时读取"));
    if(m_moduleLogIdleTimer)m_moduleLogIdleTimer->start();

    // Save the raw stream exactly as received. Do not synthesize line breaks between TCP chunks.
    if(m_logFile && m_logFile->isOpen()){
        m_logFile->write(text.toUtf8());
        m_logFile->flush();
    }
}

void RemoteToolDialog::flushPendingModuleLog()
{
    if(!m_output || m_pendingModuleLogText.isEmpty())return;
    const bool follow=m_output->verticalScrollBar()->value()>=m_output->verticalScrollBar()->maximum()-2;
    const QString chunk=std::exchange(m_pendingModuleLogText,QString());
    m_output->moveCursor(QTextCursor::End);
    m_output->insertPlainText(chunk);
    if(follow)m_output->verticalScrollBar()->setValue(m_output->verticalScrollBar()->maximum());

    // Analyze at the same 50 ms UI cadence instead of once per TCP chunk.
    const WanStatus status=LogAnalyzer::analyze(m_moduleLogBuffer);
    if(m_moduleLiveSummary){
        QStringList parts;
        parts<<QStringLiteral("模组 %1").arg(!status.moduleName.isEmpty()?status.moduleName:(status.moduleAtResponsive?QStringLiteral("AT正常"):QStringLiteral("--")));
        parts<<QStringLiteral("SIM %1").arg(!status.simStatus.isEmpty()?status.simStatus:QStringLiteral("--"));
        const QString reg=!status.c5greg.isEmpty()?QStringLiteral("C5GREG %1").arg(status.c5greg)
            :!status.cereg.isEmpty()?QStringLiteral("CEREG %1").arg(status.cereg)
            :!status.cgreg.isEmpty()?QStringLiteral("CGREG %1").arg(status.cgreg)
            :QStringLiteral("注册 --");
        parts<<reg;
        if(status.rsrp!=999)parts<<QStringLiteral("RSRP %1 dBm").arg(status.rsrp);
        else if(status.rssi!=999)parts<<QStringLiteral("RSSI %1 dBm").arg(status.rssi);
        else if(status.csq>=0)parts<<QStringLiteral("CSQ %1").arg(status.csq);
        if(status.rsrq!=999)parts<<QStringLiteral("RSRQ %1 dB").arg(status.rsrq);
        if(status.sinr!=999)parts<<QStringLiteral("SINR %1 dB").arg(status.sinr);
        if(!status.wanIfname.isEmpty())parts<<QStringLiteral("WAN %1").arg(status.wanIfname);
        if(!status.wanIp.isEmpty()&&status.wanIp!=QStringLiteral("0.0.0.0"))parts<<QStringLiteral("IP %1").arg(status.wanIp);
        if(!status.dcuIp.isEmpty())parts<<QStringLiteral("终端 %1:%2").arg(status.dcuIp).arg(status.dcuPort>0?status.dcuPort:0);
        m_moduleLiveSummary->setText(QStringLiteral("实时提取：%1").arg(parts.join(QStringLiteral(" | "))));
    }
    updateModuleLogRuntimeLabel();
}

void RemoteToolDialog::updateModuleLogRuntimeLabel()
{
    if(!m_moduleLogRuntime)return;
    QString state=QStringLiteral("未启动");
    if(m_moduleLogSetupState==ModuleLogSetupState::Tailing)state=QStringLiteral("实时读取中");
    else if(m_moduleLogSetupState!=ModuleLogSetupState::Idle)state=QStringLiteral("准备中");
    const QString last=m_lastModuleLogDataTime.isEmpty()?QStringLiteral("--"):m_lastModuleLogDataTime;
    m_moduleLogRuntime->setText(QStringLiteral("模块日志实时读取：%1 | 命令：tail /tmp/.systemlog -f | 最近数据：%2 | 已接收：%3 行")
        .arg(state,last).arg(m_moduleLogLineCount));
}

QString RemoteToolDialog::moduleLogDirectory() const
{
    QString documents=QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if(documents.isEmpty())documents=QDir::homePath()+QStringLiteral("/Documents");
    return QDir(documents).filePath(QStringLiteral("FourFaith_RouterDiag/logs"));
}

bool RemoteToolDialog::prepareModuleLogFile()
{
    if(m_mode!=Mode::ModuleLog || !m_logFile)return false;
    closeModuleLogFile();
    QDir dir(moduleLogDirectory());
    if(!dir.exists() && !dir.mkpath(QStringLiteral(".")))return false;
    QString host=m_params.host.trimmed();
    host.replace(QRegularExpression(QStringLiteral(R"([^A-Za-z0-9._-])")),QStringLiteral("_"));
    if(host.isEmpty())host=QStringLiteral("router");
    const QString filename=QStringLiteral("module_%1_%2.log").arg(host,QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    m_activeLogPath=dir.filePath(filename);
    m_logFile->setFileName(m_activeLogPath);
    if(!m_logFile->open(QIODevice::WriteOnly|QIODevice::Append|QIODevice::Text)){
        m_activeLogPath.clear();
        return false;
    }
    if(m_logPathLabel)m_logPathLabel->setText(QStringLiteral("正在保存：%1").arg(QDir::toNativeSeparators(m_activeLogPath)));
    return true;
}

void RemoteToolDialog::closeModuleLogFile()
{
    if(m_logFile && m_logFile->isOpen()){
        m_logFile->flush();
        m_logFile->close();
    }
    if(m_mode==Mode::ModuleLog && m_logPathLabel){
        const QString text=m_activeLogPath.isEmpty()?QStringLiteral("默认保存：%1").arg(QDir::toNativeSeparators(moduleLogDirectory()))
            :QStringLiteral("已保存：%1").arg(QDir::toNativeSeparators(m_activeLogPath));
        m_logPathLabel->setText(text);
    }
}

void RemoteToolDialog::openModuleLogFolder()
{
    QDir dir(moduleLogDirectory());
    if(!dir.exists())dir.mkpath(QStringLiteral("."));
    QDesktopServices::openUrl(QUrl::fromLocalFile(dir.absolutePath()));
}

void RemoteToolDialog::saveModuleLogAs()
{
    const QString target=QFileDialog::getSaveFileName(this,QStringLiteral("模块日志另存为"),
        QStringLiteral("module_%1.log").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        QStringLiteral("日志文件 (*.log *.txt);;所有文件 (*.*)"));
    if(target.isEmpty())return;
    if(m_logFile && m_logFile->isOpen())m_logFile->flush();

    if(!m_activeLogPath.isEmpty() && QFileInfo::exists(m_activeLogPath)){
        QFile::remove(target);
        if(QFile::copy(m_activeLogPath,target)){
            m_status->setText(QStringLiteral("日志已另存为 %1").arg(QDir::toNativeSeparators(target)));
            return;
        }
    }

    QSaveFile file(target);
    if(!file.open(QIODevice::WriteOnly|QIODevice::Text)){
        QMessageBox::warning(this,QStringLiteral("保存失败"),file.errorString());
        return;
    }
    file.write(m_output?m_output->toPlainText().toUtf8():QByteArray());
    if(!file.commit())QMessageBox::warning(this,QStringLiteral("保存失败"),file.errorString());
    else m_status->setText(QStringLiteral("日志已另存为 %1").arg(QDir::toNativeSeparators(target)));
}

void RemoteToolDialog::loadQuickCommands()
{
    if(!m_command)return;m_command->clear();
    struct BuiltinCommand { QString category; QString name; QString command; QString note; };
    const QList<BuiltinCommand> builtins={
        {QStringLiteral("只读检查"),QStringLiteral("查看网口"),QStringLiteral("ifconfig"),QStringLiteral("查看接口、IPv4地址和链路状态")},
        {QStringLiteral("只读检查"),QStringLiteral("查看接口流量"),QStringLiteral("cat /proc/net/dev"),QStringLiteral("查看各接口收发字节/包统计")},
        {QStringLiteral("只读检查"),QStringLiteral("查看ARP"),QStringLiteral("cat /proc/net/arp"),QStringLiteral("查看ARP邻居表")},
        {QStringLiteral("只读检查"),QStringLiteral("查看DNS"),QStringLiteral("cat /etc/resolv.conf"),QStringLiteral("查看DNS服务器配置")},
        {QStringLiteral("只读检查"),QStringLiteral("查看路由"),QStringLiteral("route -n"),QStringLiteral("查看路由、网关和出口接口")},
        {QStringLiteral("只读检查"),QStringLiteral("查看默认路由"),QStringLiteral("route -n | grep '^0.0.0.0'"),QStringLiteral("快速查看当前默认路由和出口接口")},
        {QStringLiteral("只读检查"),QStringLiteral("查看主WAN"),QStringLiteral("nvram get wan_proto; nvram get wan_ifname; nvram get wan_ipaddr; nvram get wan_gateway; nvram get wan_get_dns"),QStringLiteral("只读取主WAN协议、接口、IP、网关和DNS")},
        {QStringLiteral("只读检查"),QStringLiteral("查看备WAN"),QStringLiteral("nvram get bkup_wan_proto; nvram get bkup_wan_ifname; nvram get bkup_wan_ipaddr; nvram get bkup_wan_gateway; nvram get bkup_wan_get_dns"),QStringLiteral("只读取备用WAN关键状态；无备用链时字段可为空")},
        {QStringLiteral("只读检查"),QStringLiteral("查看接口状态"),QStringLiteral("for i in /sys/class/net/*; do echo \"$i: $(cat $i/operstate 2>/dev/null)\"; done"),QStringLiteral("查看Linux网口operstate")},
        {QStringLiteral("只读检查"),QStringLiteral("WAN接口"),QStringLiteral("nvram get wan_ifname"),QStringLiteral("读取WAN接口名")},
        {QStringLiteral("只读检查"),QStringLiteral("WAN IP"),QStringLiteral("nvram get wan_ipaddr"),QStringLiteral("读取WAN IPv4地址")},
        {QStringLiteral("只读检查"),QStringLiteral("查看网络连接"),QStringLiteral("netstat -an"),QStringLiteral("查看连接与监听端口")},
        {QStringLiteral("只读检查"),QStringLiteral("查看2404连接"),QStringLiteral("netstat -an | grep 2404"),QStringLiteral("快速查看IEC104常用2404端口会话")},
        {QStringLiteral("只读检查"),QStringLiteral("查看监听端口"),QStringLiteral("netstat -an | grep LISTEN"),QStringLiteral("查看当前TCP监听端口")},
        {QStringLiteral("只读检查"),QStringLiteral("查看防火墙"),QStringLiteral("iptables -L -n -v"),QStringLiteral("查看filter表规则与计数")},
        {QStringLiteral("只读检查"),QStringLiteral("查看NAT"),QStringLiteral("iptables -t nat -L -n -v"),QStringLiteral("查看NAT规则与命中计数")},
        {QStringLiteral("抓包分析"),QStringLiteral("检查抓包工具"),QStringLiteral("which tcpdump; tcpdump --version 2>&1 | head -n 2"),QStringLiteral("确认tcpdump可用性和版本")},
        {QStringLiteral("抓包分析"),QStringLiteral("查看抓包接口"),QStringLiteral("tcpdump -D 2>/dev/null || ifconfig -a"),QStringLiteral("查看tcpdump可见接口；不自动把br0当WAN")},
        {QStringLiteral("只读检查"),QStringLiteral("查看模组串口"),QStringLiteral("ls -l /dev/ttyUSB* /dev/ttyACM* 2>/dev/null"),QStringLiteral("查看候选模组AT串口节点")},
        {QStringLiteral("只读检查"),QStringLiteral("查看模组和信号"),QStringLiteral("nvram get modulename; nvram get submodulename; nvram get current_module_real_name; nvram get current_module_name; nvram get comm_name; nvram get comm_module_status; nvram get comm_network; nvram get comm_dial_status; nvram get comm_rsrp; nvram get comm_rsrq; nvram get comm_sinr; nvram get comm_csq"),QStringLiteral("读取模组运行标识、网络制式、拨号和信号关键值，不读取IMSI/IMEI/ICCID")},
        {QStringLiteral("日志"),QStringLiteral("查看日志状态"),QStringLiteral("nvram get debuglog_enable; nvram get syslogd_enable"),QStringLiteral("查看debuglog/syslog输出模式")},
        {QStringLiteral("日志"),QStringLiteral("查看最近日志"),QStringLiteral("logread | tail -n 200"),QStringLiteral("查看最近200行系统日志")},
        {QStringLiteral("日志"),QStringLiteral("跟踪实时日志"),QStringLiteral("tail /tmp/.systemlog -f"),QStringLiteral("持续查看系统日志；点击停止结束tail")},
        {QStringLiteral("日志"),QStringLiteral("开启系统日志"),QStringLiteral("nvram set debuglog_enable=1; nvram commit"),QStringLiteral("写NVRAM：启用系统日志")},
        {QStringLiteral("日志"),QStringLiteral("关闭系统日志"),QStringLiteral("nvram set debuglog_enable=0; nvram commit"),QStringLiteral("写NVRAM：关闭系统日志")},
        {QStringLiteral("日志"),QStringLiteral("网口Telnet日志输出"),QStringLiteral("nvram set syslogd_enable=3; nvram commit"),QStringLiteral("网页/网口Telnet通过/tmp/.systemlog读取")},
        {QStringLiteral("日志"),QStringLiteral("串口日志输出"),QStringLiteral("nvram set syslogd_enable=0; nvram commit"),QStringLiteral("系统日志直接输出到串口")},
        {QStringLiteral("只读检查"),QStringLiteral("查看内核日志"),QStringLiteral("dmesg | tail -n 200"),QStringLiteral("最近200行内核日志")},
        {QStringLiteral("只读检查"),QStringLiteral("查看进程"),QStringLiteral("ps"),QStringLiteral("查看当前进程")},
        {QStringLiteral("只读检查"),QStringLiteral("查看系统版本"),QStringLiteral("uname -a; cat /proc/version"),QStringLiteral("查看内核和系统版本")},
        {QStringLiteral("只读检查"),QStringLiteral("查看系统时间"),QStringLiteral("date"),QStringLiteral("查看路由器当前系统时间")},
        {QStringLiteral("只读检查"),QStringLiteral("查看系统负载"),QStringLiteral("cat /proc/loadavg; cat /proc/uptime"),QStringLiteral("查看负载、运行时间和调度状态")},
        {QStringLiteral("只读检查"),QStringLiteral("查看磁盘"),QStringLiteral("df -h"),QStringLiteral("查看文件系统空间")},
        {QStringLiteral("只读检查"),QStringLiteral("查看内存"),QStringLiteral("free"),QStringLiteral("查看内存使用")},
        {QStringLiteral("只读检查"),QStringLiteral("查看运行时间"),QStringLiteral("uptime"),QStringLiteral("查看运行时间和负载")},
        {QStringLiteral("维护操作"),QStringLiteral("重启路由器"),QStringLiteral("reboot"),QStringLiteral("危险操作：立即重启路由器；执行前会二次确认")}
    };

    // User-defined commands are loaded first. If a user intentionally saves a
    // command with the same display name as a built-in (for example “查看进程”),
    // findText/current selection should resolve to the user's entry rather than
    // silently shadowing it with the built-in one. Built-ins are still appended
    // afterwards and remain available in the table.
    QSettings settings(QStringLiteral("FourFaith"),settingsApplicationName());
    const int count=settings.beginReadArray(QStringLiteral("remoteCommands/custom"));
    for(int i=0;i<count;++i){settings.setArrayIndex(i);const QString name=settings.value(QStringLiteral("name")).toString().trimmed();const QString command=settings.value(QStringLiteral("command")).toString().trimmed();const QString note=settings.value(QStringLiteral("note")).toString().trimmed();const QString category=settings.value(QStringLiteral("category"),QStringLiteral("自定义")).toString().trimmed();if(!name.isEmpty()&&!command.isEmpty())addCommandItem(m_command,name,command,false,note,category);}
    settings.endArray();
    for(const auto& item:builtins)addCommandItem(m_command,item.name,item.command,true,item.note,item.category);
}

void RemoteToolDialog::rebuildQuickCommandTable()
{
    if(!m_commandTable||!m_command)return;
    m_commandTable->setRowCount(m_command->count());
    QStringList categories;
    for(int row=0;row<m_command->count();++row){
        const QString category=m_command->itemData(row,CategoryRole).toString().isEmpty()?QStringLiteral("自定义"):m_command->itemData(row,CategoryRole).toString();
        if(!categories.contains(category))categories<<category;
        auto* categoryItem=new QTableWidgetItem(category);auto* nameItem=new QTableWidgetItem(m_command->itemText(row));auto* commandItem=new QTableWidgetItem(m_command->itemData(row,CommandRole).toString());auto* noteItem=new QTableWidgetItem(m_command->itemData(row,NoteRole).toString());
        if(m_command->itemData(row,BuiltinRole).toBool())nameItem->setToolTip(QStringLiteral("内置快捷指令，不可删除或修改"));
        m_commandTable->setItem(row,0,categoryItem);m_commandTable->setItem(row,1,nameItem);m_commandTable->setItem(row,2,commandItem);m_commandTable->setItem(row,3,noteItem);m_commandTable->setRowHeight(row,30);
    }
    if(m_commandCategoryFilter){
        const QString current=m_commandCategoryFilter->currentText();m_commandCategoryFilter->blockSignals(true);m_commandCategoryFilter->clear();m_commandCategoryFilter->addItem(QStringLiteral("全部分类"));categories.sort();m_commandCategoryFilter->addItems(categories);const int idx=m_commandCategoryFilter->findText(current);m_commandCategoryFilter->setCurrentIndex(idx>=0?idx:0);m_commandCategoryFilter->blockSignals(false);
    }
}

void RemoteToolDialog::saveQuickCommands() const
{
    if(!m_command)return;
    QSettings settings(QStringLiteral("FourFaith"),settingsApplicationName());
    settings.remove(QStringLiteral("remoteCommands/custom"));
    settings.beginWriteArray(QStringLiteral("remoteCommands/custom"));
    int out=0;
    for(int i=0;i<m_command->count();++i){
        if(m_command->itemData(i,BuiltinRole).toBool())continue;
        settings.setArrayIndex(out++);
        settings.setValue(QStringLiteral("name"),m_command->itemText(i));
        settings.setValue(QStringLiteral("command"),m_command->itemData(i,CommandRole).toString());
        settings.setValue(QStringLiteral("note"),m_command->itemData(i,NoteRole).toString());
        settings.setValue(QStringLiteral("category"),m_command->itemData(i,CategoryRole).toString());
    }
    settings.endArray();
    settings.sync();
}

void RemoteToolDialog::syncCommandFromSelection()
{
    if(!m_command || !m_commandText)return;
    const int index=m_command->currentIndex();
    if(index<0)return;
    m_commandText->setText(m_command->itemData(index,CommandRole).toString());
    const bool builtin=m_command->itemData(index,BuiltinRole).toBool();
    if(m_commandEdit)m_commandEdit->setEnabled(!builtin);
    if(m_commandDelete)m_commandDelete->setEnabled(!builtin);
}

void RemoteToolDialog::commandQuickCommandSelected(int row)
{
    if(!m_command||!m_commandTable||row<0||row>=m_command->count())return;
    m_command->setCurrentIndex(row);
    syncCommandFromSelection();
    m_commandTable->selectRow(row);
}

void RemoteToolDialog::addQuickCommand()
{
    if(!m_command)return;
    QString name;
    QString command=m_commandText?m_commandText->text().trimmed():QString();
    QString note;QString category=QStringLiteral("自定义");
    if(!editQuickCommandDialog(this,QStringLiteral("新增快捷指令"),name,command,note,category))return;
    addCommandItem(m_command,name,command,false,note,category);
    saveQuickCommands();
    rebuildQuickCommandTable();
    const int row=m_command->count()-1;
    if(row>=0)commandQuickCommandSelected(row);
}

void RemoteToolDialog::editQuickCommand()
{
    if(!m_command)return;
    const int index=m_command->currentIndex();
    if(index<0)return;
    if(m_command->itemData(index,BuiltinRole).toBool()){
        QMessageBox::information(this,QStringLiteral("内置指令"),QStringLiteral("内置指令不能修改；可以新增一条自己的快捷指令。"));
        return;
    }
    QString name=m_command->itemText(index);
    QString command=m_command->itemData(index,CommandRole).toString();
    QString note=m_command->itemData(index,NoteRole).toString();
    QString category=m_command->itemData(index,CategoryRole).toString();
    if(!editQuickCommandDialog(this,QStringLiteral("编辑快捷指令"),name,command,note,category))return;
    m_command->setItemText(index,name);
    m_command->setItemData(index,command,CommandRole);
    m_command->setItemData(index,note,NoteRole);
    m_command->setItemData(index,category,CategoryRole);
    m_command->setItemData(index,command,Qt::ToolTipRole);
    saveQuickCommands();
    rebuildQuickCommandTable();
    commandQuickCommandSelected(index);
}

void RemoteToolDialog::deleteQuickCommand()
{
    if(!m_command)return;
    const int index=m_command->currentIndex();
    if(index<0)return;
    if(m_command->itemData(index,BuiltinRole).toBool()){
        QMessageBox::information(this,QStringLiteral("内置指令"),QStringLiteral("内置指令不能删除。"));
        return;
    }
    if(QMessageBox::question(this,QStringLiteral("删除快捷指令"),QStringLiteral("确定删除“%1”？").arg(m_command->itemText(index)),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    m_command->removeItem(index);
    saveQuickCommands();
    rebuildQuickCommandTable();
    if(m_command->count()>0)commandQuickCommandSelected(qMin(index,m_command->count()-1));
    else if(m_commandText)m_commandText->clear();
}


void RemoteToolDialog::exportQuickCommands()
{
    if(!m_command)return;
    const QString path=QFileDialog::getSaveFileName(this,QStringLiteral("导出快捷命令"),
        QDir::homePath()+QStringLiteral("/FourFaith_quick_commands.json"),QStringLiteral("JSON (*.json)"));
    if(path.isEmpty())return;

    QJsonArray commands;
    for(int i=0;i<m_command->count();++i){
        QJsonObject item;
        item.insert(QStringLiteral("name"),m_command->itemText(i));
        item.insert(QStringLiteral("command"),m_command->itemData(i,CommandRole).toString());
        item.insert(QStringLiteral("note"),m_command->itemData(i,NoteRole).toString());
        item.insert(QStringLiteral("category"),m_command->itemData(i,CategoryRole).toString());
        item.insert(QStringLiteral("builtin"),m_command->itemData(i,BuiltinRole).toBool());
        commands.append(item);
    }
    QJsonObject root;
    root.insert(QStringLiteral("format"),QStringLiteral("FourFaith.RouterDiag.QuickCommands"));
    root.insert(QStringLiteral("version"),2);
    root.insert(QStringLiteral("commands"),commands);
    QSaveFile file(path);
    if(!file.open(QIODevice::WriteOnly)){
        QMessageBox::warning(this,QStringLiteral("导出失败"),file.errorString());
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    if(!file.commit()) QMessageBox::warning(this,QStringLiteral("导出失败"),file.errorString());
    else m_status->setText(QStringLiteral("已导出 %1 条快捷命令：%2").arg(commands.size()).arg(QDir::toNativeSeparators(path)));
}

void RemoteToolDialog::importQuickCommands()
{
    if(!m_command)return;
    const QString path=QFileDialog::getOpenFileName(this,QStringLiteral("导入快捷命令"),QDir::homePath(),QStringLiteral("JSON (*.json)"));
    if(path.isEmpty())return;
    QFile file(path);
    if(!file.open(QIODevice::ReadOnly)){
        QMessageBox::warning(this,QStringLiteral("导入失败"),file.errorString());
        return;
    }
    QJsonParseError parseError;
    const auto doc=QJsonDocument::fromJson(file.readAll(),&parseError);
    if(parseError.error!=QJsonParseError::NoError || !doc.isObject()){
        QMessageBox::warning(this,QStringLiteral("导入失败"),QStringLiteral("JSON格式无效：%1").arg(parseError.errorString()));
        return;
    }
    const auto root=doc.object();
    if(root.value(QStringLiteral("format")).toString()!=QStringLiteral("FourFaith.RouterDiag.QuickCommands") || !root.value(QStringLiteral("commands")).isArray()){
        QMessageBox::warning(this,QStringLiteral("导入失败"),QStringLiteral("不是有效的四信路由诊断快捷命令文件"));
        return;
    }

    auto uniqueName=[this](QString base){
        base=base.trimmed();
        if(base.isEmpty())base=QStringLiteral("导入命令");
        auto exists=[this](const QString& candidate){
            for(int i=0;i<m_command->count();++i)if(m_command->itemText(i).compare(candidate,Qt::CaseInsensitive)==0)return true;
            return false;
        };
        if(!exists(base))return base;
        QString candidate=base+QStringLiteral("（导入）");
        if(!exists(candidate))return candidate;
        for(int n=2;;++n){
            candidate=base+QStringLiteral("（导入%1）").arg(n);
            if(!exists(candidate))return candidate;
        }
    };

    int imported=0,skipped=0;
    const auto array=root.value(QStringLiteral("commands")).toArray();
    for(const auto& value:array){
        if(!value.isObject()){++skipped;continue;}
        const auto item=value.toObject();
        const QString command=item.value(QStringLiteral("command")).toString().trimmed();
        if(command.isEmpty()){++skipped;continue;}
        const QString name=uniqueName(item.value(QStringLiteral("name")).toString());
        const QString note=item.value(QStringLiteral("note")).toString().trimmed();
        const QString category=item.value(QStringLiteral("category")).toString(QStringLiteral("自定义")).trimmed();
        // Imported entries are always custom copies; built-in entries are never overwritten.
        addCommandItem(m_command,name,command,false,note,category.isEmpty()?QStringLiteral("自定义"):category);
        ++imported;
    }
    saveQuickCommands();
    rebuildQuickCommandTable();
    if(imported>0)commandQuickCommandSelected(m_command->count()-imported);
    m_status->setText(QStringLiteral("已导入 %1 条快捷命令（全部作为自定义副本），跳过 %2 条").arg(imported).arg(skipped));
}

void RemoteToolDialog::closeEvent(QCloseEvent* event)
{
    if(m_moduleLogRefreshTimer)m_moduleLogRefreshTimer->stop();
    if(m_moduleLogIdleTimer)m_moduleLogIdleTimer->stop();
    flushPendingModuleLog();
    closeModuleLogFile();
    if(m_client)m_client->disconnectFromHost();
    QDialog::closeEvent(event);
}
