#pragma once

#include <QDialog>
#include <QString>

class TelnetClient;
class QCheckBox;
class QComboBox;
class QEvent;
class QFile;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTimer;

struct RemoteConnectionParams {
    QString host;
    quint16 port=23;
    QString user;
    QString password;
};

class RemoteToolDialog : public QDialog {
    Q_OBJECT
public:
    enum class Mode { Ping, Command, ModuleLog };
    RemoteToolDialog(Mode mode,const RemoteConnectionParams& params,const QString& initialTarget=QString(),QWidget* parent=nullptr);
    ~RemoteToolDialog() override;

    static bool commandNeedsConfirmation(const QString& command);

protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* watched,QEvent* event) override;

private:
    void buildUi(const QString& initialTarget);
    void ensureConnectedAndRun();
    void runPendingAction();
    void appendText(const QString& text);
    void queueModuleLogText(const QString& text);
    void flushPendingModuleLog();
    void beginModuleLogTail();
    void updateModuleLogRuntimeLabel();

    QString moduleLogDirectory() const;
    bool prepareModuleLogFile();
    void closeModuleLogFile();
    void openModuleLogFolder();
    void saveModuleLogAs();

    void loadQuickCommands();
    void saveQuickCommands() const;
    void syncCommandFromSelection();
    void rebuildQuickCommandTable();
    void commandQuickCommandSelected(int row);
    void addQuickCommand();
    void editQuickCommand();
    void deleteQuickCommand();
    void exportQuickCommands();
    void importQuickCommands();

    Mode m_mode;
    RemoteConnectionParams m_params;
    TelnetClient* m_client=nullptr;
    QLabel* m_status=nullptr;
    QLineEdit* m_target=nullptr;
    QSpinBox* m_count=nullptr;
    QComboBox* m_command=nullptr;
    QComboBox* m_commandCategoryFilter=nullptr;
    QLineEdit* m_commandSearch=nullptr;
    QTableWidget* m_commandTable=nullptr;
    QLineEdit* m_commandText=nullptr;
    QLineEdit* m_interactiveInput=nullptr;
    QCheckBox* m_interactiveTerminal=nullptr;
    QPlainTextEdit* m_output=nullptr;
    QPushButton* m_start=nullptr;
    QPushButton* m_stop=nullptr;

    QCheckBox* m_autoSaveLog=nullptr;
    QPushButton* m_openLogFolder=nullptr;
    QPushButton* m_saveLogAs=nullptr;
    QLabel* m_logPathLabel=nullptr;
    QLabel* m_moduleLiveSummary=nullptr;
    QLabel* m_moduleLogRuntime=nullptr;
    QTimer* m_moduleLogRefreshTimer=nullptr;
    QTimer* m_moduleLogIdleTimer=nullptr;
    QString m_pendingModuleLogText;
    qint64 m_moduleLogLineCount=0;
    QString m_lastModuleLogDataTime;
    QString m_moduleLogBuffer;
    enum class ModuleLogSetupState { Idle, CheckingDebug, SettingDebug, CommitDebug, CheckingSyslog, SettingSyslog, CommitSyslog, Tailing };
    ModuleLogSetupState m_moduleLogSetupState=ModuleLogSetupState::Idle;
    QFile* m_logFile=nullptr;
    QString m_activeLogPath;

    QPushButton* m_commandAdd=nullptr;
    QPushButton* m_commandEdit=nullptr;
    QPushButton* m_commandDelete=nullptr;
    QPushButton* m_commandExport=nullptr;
    QPushButton* m_commandImport=nullptr;

    bool m_waitingLogin=false;
    bool m_actionPending=false;
};
