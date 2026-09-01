#pragma once
#include <QObject>
#include <QFile>
#include <QTimer>
#include <QTemporaryFile>
#include "PcapStreamReader.h"
#include "PacketAnalyzer.h"
#include "TcpdumpTextStreamParser.h"
class TelnetClient;
class PacketCaptureController : public QObject {
    Q_OBJECT
public:
    PacketCaptureController(TelnetClient* control,TelnetClient* capture,QObject* parent=nullptr);
    void start(const QString& iface,const QString& filter=QString());
    void setSingleSession(bool enabled){m_singleSession=enabled;}
    bool singleSession() const{return m_singleSession;}
    void stop();
    bool exportBufferedPcap(const QString& path,QString* error=nullptr) const;
    bool setDirectSavePath(const QString& path,QString* error=nullptr);
    void clearDirectSave();
    QByteArray bufferedPcap() const;
    CaptureStats stats() const{return m_analyzer.stats();}
    bool isRunning() const{return m_running;}
    bool isStarted() const{return m_started;}
    static QString buildTcpdumpCommand(const QString& iface,const QString& filter);
    static QString buildPreflightCommand(const QString& iface,const QString& filter);
    static QString buildTextTcpdumpCommand(const QString& iface,const QString& filter);
    static QString buildBackgroundTextTcpdumpCommand(const QString& iface,const QString& filter);
    static QString buildCapturePrepCommand();
    static QString buildErrorProbeCommand();
signals:
    void captureStarting(const QString& status);
    void captureStarted();
    void captureStopped();
    void captureError(const QString& error);
    void packetReady(const ParsedPacket& packet);
    void statsUpdated(const CaptureStats& stats);
    void captureBytes(quint64 bytes);
private:
    void onRaw(const QByteArray& bytes);
    void onControlCommand(const QString& command,const QString& output);
    void onCaptureCommand(const QString& command,const QString& output);
    void prepareCaptureSession();
    void beginBinaryCapture();
    void beginSingleSessionTextCapture();
    void beginTextFallbackCapture();
    void probeStartupError();
    void failStart(const QString& error,bool disconnectCapture=false);
    TelnetClient* activeCaptureClient() const;
    void finishSingleSessionStop();
    void finishSingleSessionTextCapture(const QString& output);
    void finishTextFallbackCapture(const QString& output);
    void completeBackgroundTextCaptureStart(const QString& output);
    void beginSharedTextCaptureStop();
    void verifySharedShellReady();

    TelnetClient* m_control;
    TelnetClient* m_capture;
    PcapStreamReader m_reader;
    PacketAnalyzer m_analyzer;
    TcpdumpTextStreamParser m_textStreamParser;
    QByteArray m_raw; // retained only for compatibility; full capture is streamed to m_tempCapture
    QTemporaryFile m_tempCapture;
    QFile m_direct;
    QTimer m_startupTimer;
    QString m_pendingIface;
    QString m_pendingFilter;
    QString m_preflightCommand;
    QString m_capturePrepCommand;
    QString m_errorProbeCommand;
    QString m_tcpdumpCommand;
    QString m_textCaptureCommand;
    QString m_backgroundTextCaptureCommand;
    QString m_textCapturePid;
    QString m_sharedStopCommand;
    QString m_sharedReadyCommand=QStringLiteral("echo __FF_SERIAL_READY__");
    QString m_restoreTtyCommand=QStringLiteral("stty sane echo");
    quint64 m_bytes=0;
    bool m_running=false;
    bool m_starting=false;
    bool m_started=false;
    bool m_binaryStarted=false;
    bool m_stopping=false;
    bool m_waitingErrorProbe=false;
    bool m_singleSession=false;
    bool m_textFallbackActive=false;
    bool m_textFallbackPendingKill=false;
    QString m_textFallbackKillCommand;
};
