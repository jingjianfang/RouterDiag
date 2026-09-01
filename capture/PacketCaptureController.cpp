#include "PacketCaptureController.h"
#include "PacketParser.h"
#include "TcpdumpTextPcapConverter.h"
#include "telnet/TelnetClient.h"
#include <QRegularExpression>
#include <QStringList>
#include <QFile>
#include <QDir>

namespace {
constexpr auto kTcpdumpErrorFile = "/tmp/wandiag_tcpdump.err";

QString safeIface(QString iface)
{
    iface.remove(QRegularExpression(QStringLiteral("[^A-Za-z0-9_.:-]")));
    return iface;
}

QString shellSingleQuoted(QString value)
{
    value.replace(QStringLiteral("'"),QStringLiteral("'\\''"));
    return QStringLiteral("'%1'").arg(value);
}

QString cleanRouterCommandOutput(const QString& output,const QString& command)
{
    QStringList cleaned;
    const QStringList lines=output.split(QRegularExpression(QStringLiteral("[\\r\\n]+")),Qt::SkipEmptyParts);
    const QRegularExpression prompt(QStringLiteral("^[^\\r\\n]{0,100}[#$>]\\s*$"));
    for(QString line:lines){
        line=line.trimmed();
        if(line.isEmpty()||line==command||prompt.match(line).hasMatch()||line==QStringLiteral("[COMMAND TIMEOUT]"))continue;
        cleaned<<line;
    }
    QString detail=cleaned.join(QStringLiteral(" | "));
    if(detail.size()>400)detail=detail.left(400)+QStringLiteral("...");
    return detail;
}

bool tcpdumpDetailLooksFatal(const QString& detail)
{
    const QString d=detail.toLower();
    if(d.trimmed().isEmpty())return false;
    const QStringList fatalMarkers={
        QStringLiteral("no such device"),QStringLiteral("permission denied"),QStringLiteral("syntax error"),
        QStringLiteral("parse error"),QStringLiteral("invalid"),QStringLiteral("unknown option"),
        QStringLiteral("not found"),QStringLiteral("can't"),QStringLiteral("cannot"),QStringLiteral("failed")
    };
    for(const QString& marker:fatalMarkers)if(d.contains(marker))return true;
    // Typical tcpdump startup text ("listening on ...", verbose-output notice) is stderr too,
    // but it is not a capture failure. If no fatal marker is present, prefer the text fallback.
    return false;
}
}

PacketCaptureController::PacketCaptureController(TelnetClient*c,TelnetClient*cap,QObject*p)
    :QObject(p),m_control(c),m_capture(cap)
{
    m_tempCapture.setFileTemplate(QDir::tempPath()+QStringLiteral("/FourFaith_RouterDiag_capture_XXXXXX.pcap"));
    m_tempCapture.setAutoRemove(true);
    m_startupTimer.setSingleShot(true);
    m_startupTimer.setInterval(5000);
    connect(&m_startupTimer,&QTimer::timeout,this,[this]{
        if(m_running && m_binaryStarted && !m_started)probeStartupError();
    });
    connect(m_capture,&TelnetClient::binaryReceived,this,&PacketCaptureController::onRaw);
    connect(m_control,&TelnetClient::binaryReceived,this,[this](const QByteArray& bytes){if(m_singleSession)onRaw(bytes);});
    connect(m_control,&TelnetClient::commandFinished,this,[this](const QString& command,const QString& output){
        onControlCommand(command,output);
        if(m_singleSession)onCaptureCommand(command,output);
    });
    connect(m_capture,&TelnetClient::commandFinished,this,&PacketCaptureController::onCaptureCommand);
    connect(m_control,&TelnetClient::textReceived,this,[this](const QString& text){
        if(!m_running)return;
        if(!(m_textFallbackActive || m_singleSession))return;
        const QByteArray pcapBytes=m_textStreamParser.feed(text.toLocal8Bit());
        if(!pcapBytes.isEmpty())m_reader.appendData(pcapBytes);
    });
    connect(m_control,&TelnetClient::disconnected,this,[this]{
        if(m_singleSession && m_running)finishSingleSessionStop();
    });
    connect(&m_reader,&PcapStreamReader::globalHeaderReady,this,[this](const PcapGlobalHeaderInfo&){
        if(!m_running || m_started)return;
        m_startupTimer.stop();
        m_starting=false;
        m_started=true;
        m_waitingErrorProbe=false;
        emit captureStarted();
    });
    connect(&m_reader,&PcapStreamReader::rawBytesAccepted,this,[this](const QByteArray&b){
        if(m_tempCapture.isOpen() && m_tempCapture.write(b)!=b.size())emit captureError(m_tempCapture.errorString());
        if(m_direct.isOpen() && m_direct.write(b)!=b.size())emit captureError(m_direct.errorString());
        m_bytes+=b.size();
        emit captureBytes(m_bytes);
    });
    connect(&m_reader,&PcapStreamReader::streamError,this,[this](const QString& error){
        if(m_running && !m_started)probeStartupError();
        else emit captureError(error);
    });
    connect(&m_reader,&PcapStreamReader::packetReady,this,[this](const PcapRecord&r){
        auto p=PacketParser::parse(r,m_reader.globalHeader().linkType);
        if(p.valid){m_analyzer.consume(p);emit packetReady(p);emit statsUpdated(m_analyzer.stats());}
    });
}


TelnetClient* PacketCaptureController::activeCaptureClient() const
{
    return m_singleSession?m_control:m_capture;
}

QString PacketCaptureController::buildTcpdumpCommand(const QString&i,const QString&f)
{
    const QString iface=safeIface(i);
    QString cmd=QStringLiteral("exec tcpdump -i %1 -U -s 0 -w -").arg(iface);
    if(!f.trimmed().isEmpty())cmd+=QLatin1Char(' ')+shellSingleQuoted(f.trimmed());
    cmd+=QStringLiteral(" 2>%1").arg(QString::fromLatin1(kTcpdumpErrorFile));
    return cmd;
}

QString PacketCaptureController::buildTextTcpdumpCommand(const QString&i,const QString&f)
{
    const QString iface=safeIface(i);
    QString cmd=QStringLiteral("tcpdump -i %1 -n -l -s 0 -xx").arg(iface);
    if(!f.trimmed().isEmpty())cmd+=QLatin1Char(' ')+shellSingleQuoted(f.trimmed());
    cmd+=QStringLiteral(" 2>&1");
    return cmd;
}

QString PacketCaptureController::buildBackgroundTextTcpdumpCommand(const QString&i,const QString&f)
{
    QString cmd=buildTextTcpdumpCommand(i,f);
    cmd+=QStringLiteral(" & pid=$!; echo __WANDIAG_TCPDUMP_PID__=$pid");
    return cmd;
}

QString PacketCaptureController::buildPreflightCommand(const QString&i,const QString&)
{
    const QString iface=safeIface(i);
    // The physical serial console echoes and wraps long commands.  Do not put textual
    // success/failure markers in this command: echoed marker text can be mistaken for the
    // command result. TelnetClient already captures the real shell exit status for us.
    // Return codes: 0=ready, 2=interface missing/unavailable, 127=tcpdump unavailable.
    if(iface==QStringLiteral("any"))
        return QStringLiteral("if command -v tcpdump >/dev/null 2>&1; then (exit 0); else (exit 127); fi");
    // Do not use `tcpdump -d` here. Several embedded/BusyBox-style router tcpdump
    // builds can capture normally but do not implement the desktop tcpdump -d option.
    return QStringLiteral(
        "if ! command -v tcpdump >/dev/null 2>&1; then (exit 127); "
        "elif ifconfig %1 >/dev/null 2>&1 || ip link show dev %1 >/dev/null 2>&1 || [ -e /sys/class/net/%1 ]; then (exit 0); "
        "else (exit 2); fi").arg(iface);
}

QString PacketCaptureController::buildCapturePrepCommand()
{
    // Prepare the *capture* Telnet PTY before switching it to binary mode. If raw/no-echo
    // is applied in the same line as tcpdump, the shell may echo that line into the PCAP
    // stream before stty takes effect and corrupt the global header.
    return QStringLiteral("rm -f %1; stty raw -echo").arg(QString::fromLatin1(kTcpdumpErrorFile));
}

QString PacketCaptureController::buildErrorProbeCommand()
{
    return QStringLiteral("cat %1 2>/dev/null").arg(QString::fromLatin1(kTcpdumpErrorFile));
}

void PacketCaptureController::start(const QString&i,const QString&f)
{
    if(m_running){emit captureError(QStringLiteral("已有抓包正在启动或运行"));return;}
    TelnetClient* capture=activeCaptureClient();
    if(!capture || !capture->isConnected()){emit captureError(QStringLiteral("抓包控制通道未连接"));return;}
    if(!m_control || !m_control->isConnected()){emit captureError(QStringLiteral("控制通道未连接，无法执行抓包前检查"));return;}
    if(m_control->isBusy()){emit captureError(QStringLiteral("控制 Telnet 正在执行其他命令，请等待当前任务完成后再开始抓包"));return;}
    if(capture!=m_control && capture->isBusy()){emit captureError(QStringLiteral("抓包通道正在执行其他命令，请稍候再开始抓包"));return;}
    if(i.trimmed().isEmpty()){emit captureError(QStringLiteral("抓包接口为空"));return;}

    m_raw.clear();m_bytes=0;m_reader.reset();m_analyzer.reset();m_textStreamParser.reset();
    if(!m_tempCapture.isOpen() && !m_tempCapture.open()){emit captureError(QStringLiteral("无法创建临时PCAP文件：%1").arg(m_tempCapture.errorString()));return;}
    m_tempCapture.resize(0);m_tempCapture.seek(0);
    m_stopping=false;m_running=true;m_starting=true;m_started=false;m_binaryStarted=false;m_waitingErrorProbe=false;
    m_textFallbackActive=false;m_textFallbackPendingKill=false;m_textFallbackKillCommand.clear();
    m_textCapturePid.clear();m_sharedStopCommand.clear();
    m_pendingIface=safeIface(i);m_pendingFilter=f.trimmed();
    m_preflightCommand=buildPreflightCommand(m_pendingIface,m_pendingFilter);
    m_capturePrepCommand=buildCapturePrepCommand();
    m_errorProbeCommand=buildErrorProbeCommand();
    m_tcpdumpCommand=buildTcpdumpCommand(m_pendingIface,m_pendingFilter);
    m_textCaptureCommand=buildTextTcpdumpCommand(m_pendingIface,m_pendingFilter);
    m_backgroundTextCaptureCommand=buildBackgroundTextTcpdumpCommand(m_pendingIface,m_pendingFilter);
    emit captureStarting(QStringLiteral("正在检查 tcpdump 和接口 %1...").arg(m_pendingIface));
    m_control->executeCommand(m_preflightCommand,5000);
}

void PacketCaptureController::prepareCaptureSession()
{
    if(!m_running || !m_starting)return;
    TelnetClient* capture=activeCaptureClient();
    if(!capture || !capture->isConnected()){failStart(QStringLiteral("抓包启动失败：抓包控制通道已断开"));return;}
    if(capture->isBusy()){failStart(QStringLiteral("抓包启动失败：抓包控制通道当前忙"));return;}
    capture->setMode(TelnetMode::CommandMode);
    if(m_singleSession){
        beginSingleSessionTextCapture();
        return;
    }
    emit captureStarting(QStringLiteral("接口检查通过，正在准备抓包二进制通道..."));
    capture->executeCommand(m_capturePrepCommand,3000);
}

void PacketCaptureController::beginSingleSessionTextCapture()
{
    if(!m_running || !m_starting)return;
    TelnetClient* capture=activeCaptureClient();
    if(!capture || !capture->isConnected()){failStart(QStringLiteral("抓包启动失败：串口控制台已断开"));return;}
    emit captureStarting(QStringLiteral("接口检查通过，串口模式后台启动 tcpdump 十六进制文本抓包..."));
    m_binaryStarted=false;
    m_textStreamParser.reset();
    capture->setMode(TelnetMode::CommandMode);
    capture->executeCommand(m_backgroundTextCaptureCommand,5000);
}

void PacketCaptureController::beginBinaryCapture()
{
    if(!m_running || !m_starting)return;
    m_binaryStarted=true;
    emit captureStarting(QStringLiteral("正在启动 tcpdump，并等待 PCAP 数据头..."));
    TelnetClient* capture=activeCaptureClient();
    if(!capture){failStart(QStringLiteral("抓包启动失败：抓包控制通道不存在"));return;}
    capture->setMode(TelnetMode::PcapStreamMode);
    capture->executeCommand(m_tcpdumpCommand,24*60*60*1000);
    m_startupTimer.start();
}

void PacketCaptureController::beginTextFallbackCapture()
{
    if(!m_running)return;
    m_startupTimer.stop();
    m_waitingErrorProbe=false;
    m_textFallbackPendingKill=false;
    m_textFallbackKillCommand.clear();

    // The binary Telnet session has already failed to produce a valid PCAP header.
    // Drop that session and reuse the logged-in control shell for a portable -xx text capture.
    if(m_capture && m_capture->isConnected())m_capture->disconnectFromHost();
    m_reader.reset();
    m_analyzer.reset();
    m_textStreamParser.reset();
    m_raw.clear();
    if(m_tempCapture.isOpen()){m_tempCapture.resize(0);m_tempCapture.seek(0);}
    m_bytes=0;
    m_binaryStarted=false;
    m_starting=true;
    m_started=false;
    m_textFallbackActive=true;
    m_control->setMode(TelnetMode::CommandMode);
    emit captureStarting(QStringLiteral("二进制PCAP通道未返回有效数据头，自动切换到后台 tcpdump -xx 文本抓包..."));
    m_control->executeCommand(m_backgroundTextCaptureCommand,5000);
}

void PacketCaptureController::probeStartupError()
{
    if(!m_running || m_started || m_waitingErrorProbe || m_textFallbackPendingKill || m_textFallbackActive)return;
    m_startupTimer.stop();
    if(m_control && m_control->isConnected() && !m_control->isBusy()){
        m_waitingErrorProbe=true;
        emit captureStarting(QStringLiteral("tcpdump 未返回 PCAP 数据头，正在读取路由器错误信息..."));
        m_control->executeCommand(m_errorProbeCommand,2000);
        return;
    }
    failStart(QStringLiteral("抓包启动失败：tcpdump 未返回 PCAP 数据头；当前无法读取错误信息，请检查接口、过滤表达式或 tcpdump 权限"),true);
}

void PacketCaptureController::failStart(const QString& error,bool disconnectCapture)
{
    m_startupTimer.stop();
    m_running=false;m_starting=false;m_started=false;m_binaryStarted=false;m_stopping=false;m_waitingErrorProbe=false;
    m_textFallbackActive=false;m_textFallbackPendingKill=false;m_textFallbackKillCommand.clear();
    m_textCapturePid.clear();m_sharedStopCommand.clear();
    if(m_direct.isOpen())m_direct.close();
    emit captureError(error);
    // Do not tear down a newly auto-reconnected command session after a failed binary start.
    TelnetClient* capture=activeCaptureClient();
    if(disconnectCapture && !m_singleSession && capture && capture->isConnected() && capture->mode()==TelnetMode::PcapStreamMode)
        capture->disconnectFromHost();
}

void PacketCaptureController::onRaw(const QByteArray&b){if(m_running)m_reader.appendData(b);}

void PacketCaptureController::stop()
{
    if(!m_running||m_stopping)return;
    if(m_starting && !m_binaryStarted && !(m_singleSession||m_textFallbackActive)){
        m_running=false;m_starting=false;m_started=false;m_waitingErrorProbe=false;
        if(m_direct.isOpen())m_direct.close();
        emit captureStopped();
        return;
    }
    m_stopping=true;
    m_startupTimer.stop();

    if(m_singleSession || m_textFallbackActive){
        beginSharedTextCaptureStop();
        return;
    }

    if(m_control&&m_control->isConnected()&&!m_control->isBusy())m_control->executeCommand(QStringLiteral("pidof tcpdump"),2000);
    else{
        if(m_capture&&m_capture->isConnected())m_capture->disconnectFromHost();
        m_running=false;m_starting=false;m_started=false;m_binaryStarted=false;m_stopping=false;m_waitingErrorProbe=false;
        m_textFallbackActive=false;m_textFallbackPendingKill=false;m_textFallbackKillCommand.clear();
        if(m_direct.isOpen())m_direct.close();emit captureStopped();
    }
}

void PacketCaptureController::finishSingleSessionStop()
{
    m_running=false;m_starting=false;m_started=false;m_binaryStarted=false;m_stopping=false;m_waitingErrorProbe=false;
    m_textFallbackActive=false;m_textFallbackPendingKill=false;m_textFallbackKillCommand.clear();
    m_textCapturePid.clear();m_sharedStopCommand.clear();
    if(m_direct.isOpen())m_direct.close();
    emit captureStopped();
}

void PacketCaptureController::completeBackgroundTextCaptureStart(const QString& output)
{
    if(!m_running)return;
    const QRegularExpression pidRe(QStringLiteral("__WANDIAG_TCPDUMP_PID__=(\\d+)"));
    const auto match=pidRe.match(output);
    if(!match.hasMatch()){
        if(m_stopping){m_starting=false;beginSharedTextCaptureStop();return;}
        failStart(QStringLiteral("文本抓包启动失败：未获得 tcpdump PID"));
        return;
    }
    m_textCapturePid=match.captured(1);
    m_starting=false;
    m_started=true;
    if(m_stopping){beginSharedTextCaptureStop();return;}
    emit captureStarted();
}

void PacketCaptureController::beginSharedTextCaptureStop()
{
    TelnetClient* capture=m_control;
    if(!capture || !capture->isConnected()){finishSingleSessionStop();return;}
    if(capture->isBusy()){
        // Background capture normally leaves the shared shell idle. Ctrl-C is only a
        // recovery nudge if startup or another foreground command unexpectedly remains busy.
        capture->sendInterrupt();
        QTimer::singleShot(250,this,[this]{if(m_running&&m_stopping)beginSharedTextCaptureStop();});
        return;
    }
    if(!m_textCapturePid.isEmpty()){
        m_sharedStopCommand=QStringLiteral("kill -2 %1").arg(m_textCapturePid);
        capture->executeCommand(m_sharedStopCommand,2500);
    }else{
        m_sharedStopCommand=QStringLiteral("pidof tcpdump");
        capture->executeCommand(m_sharedStopCommand,2000);
    }
}

void PacketCaptureController::verifySharedShellReady()
{
    if(!m_control || !m_control->isConnected()){finishSingleSessionStop();return;}
    m_control->executeCommand(m_sharedReadyCommand,2000);
}

void PacketCaptureController::onCaptureCommand(const QString&cmd,const QString&out)
{
    if(m_singleSession && cmd==m_backgroundTextCaptureCommand){
        completeBackgroundTextCaptureStart(out);
        return;
    }
    if(!m_running || !m_starting || cmd!=m_capturePrepCommand)return;
    if(out.contains(QStringLiteral("[COMMAND TIMEOUT]"))){
        failStart(QStringLiteral("抓包启动失败：抓包控制通道无法进入 raw/no-echo 模式"),true);
        return;
    }
    beginBinaryCapture();
}

void PacketCaptureController::finishSingleSessionTextCapture(const QString& output)
{
    if(!m_singleSession)return;
    const QByteArray tail=m_textStreamParser.finish();
    if(!tail.isEmpty())m_reader.appendData(tail);
    const bool noPackets=output.contains(QStringLiteral("0 packets captured"),Qt::CaseInsensitive) ||
                         output.contains(QStringLiteral("0 packet captured"),Qt::CaseInsensitive);
    if(!noPackets && m_textStreamParser.packetCount()==0 && !output.contains(QStringLiteral("[COMMAND TIMEOUT]")))
        emit captureError(QStringLiteral("串口抓包未解析到完整数据包；请检查接口、BPF或tcpdump -xx输出格式"));
    if(output.contains(QStringLiteral("[COMMAND TIMEOUT]")))emit captureError(QStringLiteral("串口抓包命令超时"));
    finishSingleSessionStop();
}

void PacketCaptureController::finishTextFallbackCapture(const QString& output)
{
    if(!m_textFallbackActive)return;
    const QByteArray tail=m_textStreamParser.finish();
    if(!tail.isEmpty())m_reader.appendData(tail);
    const bool noPackets=output.contains(QStringLiteral("0 packets captured"),Qt::CaseInsensitive) ||
                         output.contains(QStringLiteral("0 packet captured"),Qt::CaseInsensitive);
    if(!noPackets && m_textStreamParser.packetCount()==0 && !output.contains(QStringLiteral("[COMMAND TIMEOUT]")))
        emit captureError(QStringLiteral("文本回退抓包未解析到完整数据包；请检查接口、BPF或tcpdump输出格式"));
    if(output.contains(QStringLiteral("[COMMAND TIMEOUT]")))emit captureError(QStringLiteral("文本回退抓包命令超时"));
    finishSingleSessionStop();
}

void PacketCaptureController::onControlCommand(const QString&cmd,const QString&out)
{
    if(m_textFallbackActive && cmd==m_backgroundTextCaptureCommand){
        completeBackgroundTextCaptureStart(out);
        return;
    }

    if(m_textFallbackPendingKill){
        if(cmd==QStringLiteral("pidof tcpdump")){
            QRegularExpression re(QStringLiteral("(?:^|\\s)(\\d+)(?=\\s|$)"));
            auto match=re.match(out);
            if(match.hasMatch()){
                m_textFallbackKillCommand=QStringLiteral("kill -2 %1").arg(match.captured(1));
                m_control->executeCommand(m_textFallbackKillCommand,2000);
            }else{
                beginTextFallbackCapture();
            }
            return;
        }
        if(!m_textFallbackKillCommand.isEmpty() && cmd==m_textFallbackKillCommand){
            beginTextFallbackCapture();
            return;
        }
    }

    if(m_stopping && (m_singleSession || m_textFallbackActive)){
        if(cmd==QStringLiteral("pidof tcpdump")){
            QRegularExpression re(QStringLiteral("(?:^|\\s)(\\d+)(?=\\s|$)"));
            const auto match=re.match(out);
            if(match.hasMatch()){
                m_textCapturePid=match.captured(1);
                m_sharedStopCommand=QStringLiteral("kill -2 %1").arg(m_textCapturePid);
                m_control->executeCommand(m_sharedStopCommand,2500);
            }else verifySharedShellReady();
            return;
        }
        if(!m_sharedStopCommand.isEmpty() && cmd==m_sharedStopCommand && cmd.startsWith(QStringLiteral("kill -2 "))){
            if(out.contains(QStringLiteral("[COMMAND TIMEOUT]"))){
                m_sharedStopCommand=QStringLiteral("killall tcpdump");
                m_control->executeCommand(m_sharedStopCommand,2000);
            }else verifySharedShellReady();
            return;
        }
        if(cmd==QStringLiteral("killall tcpdump")){
            verifySharedShellReady();
            return;
        }
        if(cmd==m_sharedReadyCommand){
            if(!out.contains(QStringLiteral("__FF_SERIAL_READY__")))
                emit captureError(QStringLiteral("tcpdump 已停止，但未确认串口控制台恢复"));
            const QByteArray tail=m_textStreamParser.finish();
            if(!tail.isEmpty())m_reader.appendData(tail);
            finishSingleSessionStop();
            return;
        }
    }

    if(m_starting && cmd==m_preflightCommand){
        if(!m_running)return;
        const int rc=m_control?m_control->lastCommandExitCode():-1;
        if(out.contains(QStringLiteral("[COMMAND TIMEOUT]")) || rc<0){
            failStart(QStringLiteral("抓包前检查未取得 shell 返回码，请检查控制通道"));return;
        }
        if(rc==127){failStart(QStringLiteral("抓包启动失败：路由器未找到 tcpdump"));return;}
        if(rc==2){failStart(QStringLiteral("抓包启动失败：接口 %1 不存在或不可用").arg(m_pendingIface));return;}
        if(rc!=0){failStart(QStringLiteral("抓包前检查失败：shell 返回码 %1").arg(rc));return;}
        prepareCaptureSession();
        return;
    }

    if(m_waitingErrorProbe && cmd==m_errorProbeCommand){
        const QString detail=cleanRouterCommandOutput(out,cmd);
        if(!tcpdumpDetailLooksFatal(detail)){
            m_waitingErrorProbe=false;
            m_textFallbackPendingKill=true;
            emit captureStarting(QStringLiteral("二进制PCAP通道未返回有效数据头，正在停止该通道并自动切换到 tcpdump -xx 文本抓包..."));
            m_control->executeCommand(QStringLiteral("pidof tcpdump"),2000);
        }else{
            failStart(QStringLiteral("抓包启动失败：%1").arg(detail),true);
        }
        return;
    }

    if(!m_stopping)return;
    if(cmd==QStringLiteral("pidof tcpdump")){
        QRegularExpression re(QStringLiteral("(?:^|\\s)(\\d+)(?=\\s|$)"));auto m=re.match(out);
        if(m.hasMatch())m_control->executeCommand(QStringLiteral("kill -2 %1").arg(m.captured(1)),2000);
        else m_control->executeCommand(QStringLiteral("ps | grep '[t]cpdump'"),2000);
        return;
    }
    if(cmd==QStringLiteral("ps | grep '[t]cpdump'")){
        QRegularExpression re(QStringLiteral("^\\s*(\\d+).*tcpdump"),QRegularExpression::MultilineOption);auto m=re.match(out);
        if(m.hasMatch())m_control->executeCommand(QStringLiteral("kill -2 %1").arg(m.captured(1)),2000);
        else m_control->executeCommand(QStringLiteral("killall tcpdump"),2000);
        return;
    }
    if(cmd.startsWith(QStringLiteral("kill "))||cmd==QStringLiteral("killall tcpdump")){
        if(m_capture&&m_capture->isConnected())m_capture->disconnectFromHost();
        m_running=false;m_starting=false;m_started=false;m_binaryStarted=false;m_stopping=false;m_waitingErrorProbe=false;
        m_textFallbackActive=false;m_textFallbackPendingKill=false;m_textFallbackKillCommand.clear();
        if(m_direct.isOpen())m_direct.close();emit captureStopped();
    }
}

QByteArray PacketCaptureController::bufferedPcap() const
{
    if(!m_tempCapture.isOpen())return m_raw;
    const_cast<QTemporaryFile&>(m_tempCapture).flush();
    QFile f(m_tempCapture.fileName());
    if(!f.open(QIODevice::ReadOnly))return {};
    return f.readAll();
}

bool PacketCaptureController::exportBufferedPcap(const QString&p,QString*e)const
{
    if(m_tempCapture.isOpen()){
        const_cast<QTemporaryFile&>(m_tempCapture).flush();
        QFile::remove(p);
        if(QFile::copy(m_tempCapture.fileName(),p))return true;
        if(e)*e=QStringLiteral("复制临时PCAP失败：%1").arg(m_tempCapture.fileName());
        return false;
    }
    QFile f(p);if(!f.open(QIODevice::WriteOnly)){if(e)*e=f.errorString();return false;}
    if(f.write(m_raw)!=m_raw.size()){if(e)*e=f.errorString();return false;}return true;
}

bool PacketCaptureController::setDirectSavePath(const QString&p,QString*e)
{
    if(m_direct.isOpen())m_direct.close();m_direct.setFileName(p);
    if(!m_direct.open(QIODevice::WriteOnly)){if(e)*e=m_direct.errorString();return false;}return true;
}
void PacketCaptureController::clearDirectSave(){if(m_direct.isOpen())m_direct.close();m_direct.setFileName(QString());}
