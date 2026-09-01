#include "TelnetClient.h"

#include <QRegularExpression>
#include <QStringList>

TelnetClient::TelnetClient(QObject* parent)
    :QObject(parent)
{
    m_timer.setSingleShot(true);

    connect(&m_socket,&QTcpSocket::connected,this,&TelnetClient::connected);
    connect(&m_socket,&QTcpSocket::disconnected,this,&TelnetClient::disconnected);
    connect(&m_socket,&QTcpSocket::readyRead,this,&TelnetClient::onReadyRead);
    connect(&m_socket,&QTcpSocket::errorOccurred,this,[this](QAbstractSocket::SocketError){
        if(m_transport==TelnetTransport::Tcp)emit errorOccurred(m_socket.errorString());
    });

    connect(&m_serial,&QSerialPort::readyRead,this,&TelnetClient::onReadyRead);
    connect(&m_serial,&QSerialPort::errorOccurred,this,[this](QSerialPort::SerialPortError error){
        if(m_transport==TelnetTransport::Serial && error!=QSerialPort::NoError)
            emit errorOccurred(m_serial.errorString());
    });
    connect(&m_timer,&QTimer::timeout,this,&TelnetClient::onTimeout);
}

void TelnetClient::resetSessionState()
{
    m_timer.stop();
    m_decoder.reset();
    m_text.clear();
    m_command.clear();
    m_prompt.clear();
    m_commandMarker.clear();
    m_visibleLineBuffer.clear();
    m_lastCommandExitCode=-1;
    m_phase=Phase::Idle;
    m_mode=TelnetMode::CommandMode;
}

void TelnetClient::connectToHost(const QString& host,quint16 port)
{
    if(m_serial.isOpen()){
        m_serial.close();
        emit disconnected();
    }
    if(m_socket.state()!=QAbstractSocket::UnconnectedState)m_socket.abort();
    resetSessionState();
    m_transport=TelnetTransport::Tcp;
    m_socket.connectToHost(host,port);
}

void TelnetClient::connectToSerial(const QString& portName,
                                   qint32 baudRate,
                                   QSerialPort::DataBits dataBits,
                                   QSerialPort::Parity parity,
                                   QSerialPort::StopBits stopBits,
                                   QSerialPort::FlowControl flowControl)
{
    if(m_socket.state()!=QAbstractSocket::UnconnectedState)m_socket.abort();
    if(m_serial.isOpen())m_serial.close();
    resetSessionState();
    m_transport=TelnetTransport::Serial;

    m_serial.setPortName(portName);
    m_serial.setBaudRate(baudRate);
    m_serial.setDataBits(dataBits);
    m_serial.setParity(parity);
    m_serial.setStopBits(stopBits);
    m_serial.setFlowControl(flowControl);

    if(!m_serial.open(QIODevice::ReadWrite)){
        emit errorOccurred(QStringLiteral("无法打开串口 %1：%2").arg(portName,m_serial.errorString()));
        return;
    }

    // The router's physical console enters the same Telnet-style login prompt after
    // receiving one carriage return. Start the existing login state machine afterwards.
    m_serial.write("\r");
    m_serial.flush();
    emit connected();
}

void TelnetClient::disconnectFromHost()
{
    m_timer.stop();
    m_phase=Phase::Idle;
    if(m_transport==TelnetTransport::Serial){
        if(m_serial.isOpen()){
            m_serial.close();
            emit disconnected();
        }
        return;
    }
    if(m_socket.state()!=QAbstractSocket::UnconnectedState)m_socket.disconnectFromHost();
}

bool TelnetClient::isConnected() const
{
    if(m_transport==TelnetTransport::Serial)return m_serial.isOpen();
    return m_socket.state()==QAbstractSocket::ConnectedState;
}

qint64 TelnetClient::writeBytes(const QByteArray& bytes)
{
    if(m_transport==TelnetTransport::Serial){
        if(!m_serial.isOpen())return -1;
        return m_serial.write(bytes);
    }
    if(m_socket.state()!=QAbstractSocket::ConnectedState)return -1;
    return m_socket.write(bytes);
}

QByteArray TelnetClient::readAvailableBytes()
{
    if(m_transport==TelnetTransport::Serial)return m_serial.readAll();
    return m_socket.readAll();
}

void TelnetClient::setMode(TelnetMode mode)
{
    m_mode=mode;
    if(mode==TelnetMode::PcapStreamMode && isConnected() && m_transport==TelnetTransport::Tcp)
        m_socket.write(QByteArray::fromHex("fffd00fffb00"));
}

void TelnetClient::writeRaw(const QByteArray& bytes)
{
    if(!isConnected()){
        emit errorOccurred(QStringLiteral("Telnet/串口控制台未连接"));
        return;
    }
    writeBytes(bytes);
}

void TelnetClient::sendInterrupt()
{
    writeRaw(QByteArray(1,char(0x03)));
    if(m_transport==TelnetTransport::Serial && m_serial.isOpen())m_serial.flush();
}

void TelnetClient::writeLine(const QString& text)
{
    QByteArray bytes=text.toUtf8();
    bytes.append("\r\n");
    writeBytes(bytes);
}

void TelnetClient::login(const QString& user,const QString& password,int timeoutMs)
{
    m_user=user;
    m_password=password;
    m_phase=Phase::WaitLogin;
    m_text.clear();
    m_timer.start(timeoutMs);
}

void TelnetClient::executeCommand(const QString& command,int timeoutMs)
{
    if(!isConnected()){
        emit errorOccurred(QStringLiteral("Telnet/串口控制台未连接"));
        return;
    }
    if(m_phase!=Phase::Idle){
        emit errorOccurred(QStringLiteral("Telnet command channel is busy"));
        return;
    }
    m_command=command;
    m_text.clear();
    m_visibleLineBuffer.clear();
    m_lastCommandExitCode=-1;
    m_phase=Phase::WaitCommand;
    if(m_mode==TelnetMode::CommandMode){
        m_commandMarker=QStringLiteral("__FF_CMD_DONE_%1__").arg(++m_commandSerial);
        QString wrapped=command;
        wrapped+=QStringLiteral("; __ff_rc=$?; printf '\\n%1=%d\\n' \"$__ff_rc\"").arg(m_commandMarker);
        writeLine(wrapped);
    }else{
        m_commandMarker.clear();
        writeLine(command);
    }
    m_timer.start(timeoutMs);
}

void TelnetClient::executeStreamingCommand(const QString& command,int timeoutMs)
{
    if(!isConnected()){
        emit errorOccurred(QStringLiteral("Telnet/串口控制台未连接"));
        return;
    }
    if(m_phase!=Phase::Idle){
        emit errorOccurred(QStringLiteral("Telnet command channel is busy"));
        return;
    }
    // Long-running foreground commands (notably tcpdump -xx on a shared serial
    // console) must finish on the shell prompt after Ctrl-C.  Do not append the
    // normal completion marker: BusyBox ash may abort the remainder of a command
    // line when SIGINT terminates tcpdump, leaving the client busy until timeout.
    m_command=command;
    m_text.clear();
    m_visibleLineBuffer.clear();
    m_lastCommandExitCode=-1;
    m_commandMarker.clear();
    m_phase=Phase::WaitCommand;
    writeLine(command);
    m_timer.start(timeoutMs);
}

void TelnetClient::learnPrompt(const QString& text)
{
    const QStringList lines=text.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    for(auto it=lines.crbegin();it!=lines.crend();++it){
        const QString line=it->trimmed();
        if(line.size()<=120 && (line.endsWith(QLatin1Char('#'))||line.endsWith(QLatin1Char('$'))||line.endsWith(QLatin1Char('>')))){m_prompt=line;return;}
    }
}

bool TelnetClient::looksLikePrompt(const QString& text) const
{
    if(!m_prompt.isEmpty()){
        const QRegularExpression exact(QStringLiteral("(?:^|\\n)\\s*%1\\s*$").arg(QRegularExpression::escape(m_prompt)),QRegularExpression::MultilineOption);
        return exact.match(text).hasMatch();
    }
    return QRegularExpression(QStringLiteral("(?:^|\\n)[^\\n]{0,80}[#$>]\\s*$"),QRegularExpression::MultilineOption).match(text).hasMatch();
}

QString TelnetClient::sanitizeVisibleLine(QString line) const
{
    line=line.trimmed();
    if(line.isEmpty())return {};

    // Some BusyBox PTYs echo "prompt + command" on the same physical line. Remove
    // the learned prompt first, then run the same wrapper/marker filters below.
    if(!m_prompt.isEmpty() && line.startsWith(m_prompt)){
        line=line.mid(m_prompt.size()).trimmed();
        if(line.isEmpty())return {};
    }

    // Internal command protocol noise must never leak into user-facing panes.  The
    // physical BusyBox console may wrap the echoed shell line at arbitrary columns,
    // so match both complete markers and their wrapper fragments.
    if(line.contains(QStringLiteral("__FF_CMD_DONE_")) ||
       line.contains(QStringLiteral("__ff_rc"),Qt::CaseInsensitive) ||
       line.contains(QStringLiteral("FF_CMD_DONE")) ||
       line.contains(QStringLiteral("__FF_AT_BEGIN__")) ||
       line.contains(QStringLiteral("__FF_AT_END__")) ||
       line.contains(QStringLiteral("__FF_AT_METHOD__")) ||
       line.contains(QStringLiteral("__=%d")) ||
       line.contains(QStringLiteral("$__ff_rc"),Qt::CaseInsensitive))return {};
    if(line.startsWith(QStringLiteral("printf ")) && line.contains(QStringLiteral("__FF_")))return {};

    if(!m_command.isEmpty()){
        if(line==m_command || line.startsWith(m_command))return {};
        // Wrapped PTY echo: the first visible segment normally starts with the
        // command verb even when the completion-wrapper suffix moves to another row.
        const QString verb=m_command.section(QLatin1Char(' '),0,0).trimmed();
        if(!verb.isEmpty() && line.startsWith(verb+QLatin1Char(' ')) &&
           (line.contains(QStringLiteral(";")) || line.contains(QStringLiteral("__FF_"))))return {};
    }

    if(!m_prompt.isEmpty() && line==m_prompt)return {};
    static const QRegularExpression genericPrompt(QStringLiteral(R"(^[A-Za-z0-9_.@:/~\\-]{1,120}[#$>]\s*$)"));
    if(genericPrompt.match(line).hasMatch())return {};
    if(line.endsWith(QStringLiteral("login:"),Qt::CaseInsensitive) ||
       line.endsWith(QStringLiteral("username:"),Qt::CaseInsensitive) ||
       line.endsWith(QStringLiteral("password:"),Qt::CaseInsensitive))return {};
    return line;
}

void TelnetClient::emitVisibleTextChunk(const QString& text)
{
    QString normalized=text;
    normalized.replace(QStringLiteral("\r\n"),QStringLiteral("\n"));
    normalized.replace(QLatin1Char('\r'),QLatin1Char('\n'));
    m_visibleLineBuffer+=normalized;

    QStringList visible;
    int newline=-1;
    while((newline=m_visibleLineBuffer.indexOf(QLatin1Char('\n')))>=0){
        const QString line=m_visibleLineBuffer.left(newline);
        m_visibleLineBuffer.remove(0,newline+1);
        const QString cleaned=sanitizeVisibleLine(line);
        if(!cleaned.isEmpty())visible<<cleaned;
    }

    // Prompts and completion markers often arrive without a trailing newline. Drop
    // them immediately rather than carrying them into the next command's output.
    if(!m_visibleLineBuffer.isEmpty() && sanitizeVisibleLine(m_visibleLineBuffer).isEmpty())
        m_visibleLineBuffer.clear();

    if(!visible.isEmpty())emit visibleTextReceived(visible.join(QLatin1Char('\n'))+QLatin1Char('\n'));
}

QString TelnetClient::sanitizeCommandOutput(const QString& text) const
{
    QStringList cleaned;
    const QStringList lines=text.split(QRegularExpression(QStringLiteral("[\r\n]+")),Qt::SkipEmptyParts);
    for(const QString& rawLine:lines){
        const QString line=sanitizeVisibleLine(rawLine);
        if(!line.isEmpty())cleaned<<line;
    }
    return cleaned.join(QLatin1Char('\n'));
}

QString TelnetClient::commandOutputBeforeMarker(const QString& text) const
{
    if(m_commandMarker.isEmpty())return sanitizeCommandOutput(text);
    const QRegularExpression marker(QStringLiteral("%1=(-?\\d+)").arg(QRegularExpression::escape(m_commandMarker)));
    const auto match=marker.match(text);
    const QString before=match.hasMatch()?text.left(match.capturedStart()):text;
    return sanitizeCommandOutput(before);
}

void TelnetClient::onReadyRead()
{
    const QByteArray bytes=readAvailableBytes();
    if(bytes.isEmpty())return;

    QByteArray payload;
    if(m_transport==TelnetTransport::Tcp){
        auto decoded=m_decoder.feed(bytes);
        if(!decoded.replyBytes.isEmpty())m_socket.write(decoded.replyBytes);
        payload=decoded.payload;
    }else{
        // A physical console is not a Telnet byte stream. In particular, do not feed
        // binary PCAP bytes through TelnetDecoder because 0xFF is valid capture data.
        payload=bytes;
    }

    if(m_mode==TelnetMode::PcapStreamMode){
        if(!payload.isEmpty())emit binaryReceived(payload);
        return;
    }

    const QString text=QString::fromLocal8Bit(payload);
    if(text.isEmpty())return;
    m_text+=text;
    // Long-running commands such as tcpdump -xx / tail -f are streamed via textReceived.
    // Keep only a bounded tail for marker detection so hours of output do not accumulate in RAM.
    constexpr int MaxCommandTextBuffer=2*1024*1024;
    if(m_phase==Phase::WaitCommand && m_text.size()>MaxCommandTextBuffer)
        m_text.remove(0,m_text.size()-MaxCommandTextBuffer);
    emit textReceived(text);
    emitVisibleTextChunk(text);
    const QString low=m_text.toLower();

    if(m_phase==Phase::WaitLogin && (low.contains(QStringLiteral("login:"))||low.contains(QStringLiteral("username:")))){
        writeLine(m_user);m_text.clear();m_phase=Phase::WaitPassword;
    }else if(m_phase==Phase::WaitLogin && low.contains(QStringLiteral("password:"))){
        writeLine(m_password);m_text.clear();m_phase=Phase::WaitPrompt;
    }else if(m_phase==Phase::WaitLogin && looksLikePrompt(m_text)){
        m_timer.stop();learnPrompt(m_text);m_phase=Phase::Idle;emit loginSucceeded();
    }else if(m_phase==Phase::WaitPassword && low.contains(QStringLiteral("password:"))){
        writeLine(m_password);m_text.clear();m_phase=Phase::WaitPrompt;
    }else if((m_phase==Phase::WaitPassword||m_phase==Phase::WaitPrompt) &&
             (low.contains(QStringLiteral("login incorrect"))||low.contains(QStringLiteral("authentication failed")))){
        m_timer.stop();m_phase=Phase::Idle;emit loginFailed(QStringLiteral("Authentication failed"));
    }else if(m_phase==Phase::WaitPrompt && looksLikePrompt(m_text)){
        m_timer.stop();learnPrompt(m_text);m_phase=Phase::Idle;emit loginSucceeded();
    }else if(m_phase==Phase::WaitCommand){
        bool done=false;QString output;
        if(!m_commandMarker.isEmpty()){
            const QRegularExpression marker(QStringLiteral("%1=(-?\\d+)").arg(QRegularExpression::escape(m_commandMarker)));
            const auto match=marker.match(m_text);
            if(match.hasMatch()){m_lastCommandExitCode=match.captured(1).toInt();output=commandOutputBeforeMarker(m_text);done=true;}
        }else if(looksLikePrompt(m_text)){output=m_text;done=true;}
        if(done){
            const QString visibleTail=sanitizeVisibleLine(m_visibleLineBuffer);
            if(!visibleTail.isEmpty())emit visibleTextReceived(visibleTail);
            m_visibleLineBuffer.clear();
            m_timer.stop();const QString command=m_command;m_phase=Phase::Idle;m_commandMarker.clear();m_visibleLineBuffer.clear();emit commandFinished(command,output);
        }
    }
}

void TelnetClient::onTimeout()
{
    if(m_phase==Phase::WaitLogin||m_phase==Phase::WaitPassword||m_phase==Phase::WaitPrompt){
        m_phase=Phase::Idle;
        emit loginFailed(QStringLiteral("Telnet login timed out"));
    }else if(m_phase==Phase::WaitCommand){
        const QString command=m_command;
        m_phase=Phase::Idle;m_commandMarker.clear();m_visibleLineBuffer.clear();
        emit commandFinished(command,sanitizeCommandOutput(m_text)+QStringLiteral("\n[COMMAND TIMEOUT]"));
    }
}
