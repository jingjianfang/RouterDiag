#pragma once

#include <QWidget>
#include <QStringList>
#include <functional>
#include "capture/PcapTypes.h"

class TelnetClient;
class PacketCaptureController;
class QLineEdit;
class QComboBox;
class QPushButton;
class QTableWidget;
class QPlainTextEdit;
class QLabel;
class QCloseEvent;

struct CaptureSessionConnectionParams {
    QString host;
    quint16 port=23;
    QString user;
    QString password;
    bool serialShared=false;
    TelnetClient* sharedControl=nullptr;
    QStringList interfaces;
    bool autoRefreshInterfaces=true;
};

class CaptureSessionWidget : public QWidget {
    Q_OBJECT
public:
    explicit CaptureSessionWidget(const QString& title,const CaptureSessionConnectionParams& params,QWidget* parent=nullptr);
    ~CaptureSessionWidget() override;

    void setCaptureSpec(const QString& iface,const QString& filter);
    QString interfaceName() const;
    QString filterText() const;
    bool isRunning() const;
    void startCapture();
    void stopCapture();
    void setStartGuard(std::function<QString()> guard){m_startGuard=std::move(guard);}

signals:
    void packetObserved(const ParsedPacket& packet);
    void captureSessionStarted();
    void captureSessionStopped();
    void captureSessionFailed(const QString& reason);
    void captureSessionClosing();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void buildUi(const QString& title);
    void ensureNetworkLoggedIn();
    void tryStartController();
    void appendPacket(const ParsedPacket& packet);
    void updateStats(const CaptureStats& stats);
    void updatePreview();
    void exportPcap();
    void refreshInterfaces();
    void runInterfaceRefresh();
    void applyInterfaceList(const QString& output);

    CaptureSessionConnectionParams m_params;
    TelnetClient* m_control=nullptr;
    TelnetClient* m_capture=nullptr;
    PacketCaptureController* m_controller=nullptr;
    bool m_ownsClients=false;
    bool m_controlLogged=false;
    bool m_captureLogged=false;
    bool m_pendingStart=false;
    bool m_refreshPending=false;
    QString m_refreshCommand;
    quint64 m_no=0;
    std::function<QString()> m_startGuard;

    QComboBox* m_iface=nullptr;
    QLineEdit* m_filter=nullptr;
    QLabel* m_state=nullptr;
    QLabel* m_preview=nullptr;
    QPushButton* m_start=nullptr;
    QPushButton* m_stop=nullptr;
    QPushButton* m_export=nullptr;
    QPushButton* m_refreshInterfaces=nullptr;
    QTableWidget* m_table=nullptr;
    QPlainTextEdit* m_stats=nullptr;
    QPlainTextEdit* m_detail=nullptr;
};
