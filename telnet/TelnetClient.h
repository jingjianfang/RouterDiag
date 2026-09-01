#pragma once

#include <QObject>
#include <QSerialPort>
#include <QTcpSocket>
#include <QTimer>
#include "TelnetDecoder.h"

enum class TelnetMode { CommandMode, PcapStreamMode };
enum class TelnetTransport { Tcp, Serial };

class TelnetClient : public QObject {
    Q_OBJECT
public:
    explicit TelnetClient(QObject* parent=nullptr);

    void connectToHost(const QString& host,quint16 port=23);
    void connectToSerial(const QString& portName,
                         qint32 baudRate=115200,
                         QSerialPort::DataBits dataBits=QSerialPort::Data8,
                         QSerialPort::Parity parity=QSerialPort::NoParity,
                         QSerialPort::StopBits stopBits=QSerialPort::OneStop,
                         QSerialPort::FlowControl flowControl=QSerialPort::NoFlowControl);
    void disconnectFromHost();
    void login(const QString& user,const QString& password,int timeoutMs=5000);
    void executeCommand(const QString& command,int timeoutMs=5000);
    void executeStreamingCommand(const QString& command,int timeoutMs=5000);
    void setMode(TelnetMode mode);
    void sendInterrupt();
    void writeRaw(const QByteArray& bytes);

    TelnetMode mode() const{return m_mode;}
    TelnetTransport transport() const{return m_transport;}
    bool isSerialTransport() const{return m_transport==TelnetTransport::Serial;}
    bool isConnected() const;
    bool isBusy() const{return m_phase!=Phase::Idle;}
    int lastCommandExitCode() const{return m_lastCommandExitCode;}

signals:
    void connected();
    void disconnected();
    void loginSucceeded();
    void loginFailed(const QString& reason);
    void commandFinished(const QString& command,const QString& output);
    void textReceived(const QString& text);
    // User-visible text with shell command echoes, completion markers and prompts removed.
    void visibleTextReceived(const QString& text);
    void binaryReceived(const QByteArray& data);
    void errorOccurred(const QString& error);

private slots:
    void onReadyRead();
    void onTimeout();

private:
    enum class Phase { Idle, WaitLogin, WaitPassword, WaitPrompt, WaitCommand };

    void resetSessionState();
    void writeLine(const QString& text);
    qint64 writeBytes(const QByteArray& bytes);
    QByteArray readAvailableBytes();
    bool looksLikePrompt(const QString& text) const;
    void learnPrompt(const QString& text);
    QString commandOutputBeforeMarker(const QString& text) const;
    QString sanitizeCommandOutput(const QString& text) const;
    QString sanitizeVisibleLine(QString line) const;
    void emitVisibleTextChunk(const QString& text);

    QTcpSocket m_socket;
    QSerialPort m_serial;
    QTimer m_timer;
    TelnetDecoder m_decoder;
    TelnetMode m_mode=TelnetMode::CommandMode;
    TelnetTransport m_transport=TelnetTransport::Tcp;
    QString m_user;
    QString m_password;
    QString m_command;
    QString m_text;
    QString m_prompt;
    QString m_commandMarker;
    QString m_visibleLineBuffer;
    quint64 m_commandSerial=0;
    int m_lastCommandExitCode=-1;
    Phase m_phase=Phase::Idle;
};
