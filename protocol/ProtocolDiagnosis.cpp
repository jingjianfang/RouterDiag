#include "ProtocolDiagnosis.h"
#include "GridSecurityAnalyzer.h"
#include "Iec101Analyzer.h"
#include "Iec104Analyzer.h"

namespace {
LayerDiagnosis makeLayer(const QString& name, LayerState state, Confidence confidence,
                         const QString& conclusion, const QStringList& evidence = {},
                         const QStringList& suggestions = {})
{
    LayerDiagnosis d;
    d.layer = name;
    d.state = state;
    d.confidence = confidence;
    d.conclusion = conclusion;
    d.evidence = evidence;
    d.suggestions = suggestions;
    return d;
}

void appendUnique(QStringList& target, const QStringList& source)
{
    for (const QString& item : source) {
        if (!item.isEmpty() && !target.contains(item))
            target << item;
    }
}

QList<GridSecurityFrame> scanGridFrames(const QByteArray& bytes)
{
    QList<GridSecurityFrame> frames;
    int pos = 0;
    while (pos + 6 <= bytes.size()) {
        if (quint8(bytes.at(pos)) != 0xeb) {
            ++pos;
            continue;
        }
        const int declared = (int(quint8(bytes.at(pos + 1))) << 8) | int(quint8(bytes.at(pos + 2)));
        const int total = declared + 6;
        if (total < 9 || pos + total > bytes.size()) {
            ++pos;
            continue;
        }
        const QByteArray raw = bytes.mid(pos, total);
        const GridSecurityFrame frame = GridSecurityAnalyzer::parseRawFrame(raw);
        if (frame.valid) {
            frames << frame;
            pos += total;
        } else {
            ++pos;
        }
    }
    return frames;
}

void addGridEvidence(ProtocolEvidence& out, const GridSecurityEvidence& e)
{
    out.gridFrames += e.totalFrames;
    out.gridAuthComplete = out.gridAuthComplete || e.auth8020To8023Complete;
    out.gridSequence5051Seen = out.gridSequence5051Seen || e.sequence5051Seen;
    out.gridSequence5253Seen = out.gridSequence5253Seen || e.sequence5253Seen;
    out.gridSequence5455Seen = out.gridSequence5455Seen || e.sequence5455Seen;
    out.gridSequence6061Seen = out.gridSequence6061Seen || e.sequence6061Seen;
    out.gridRepeated56Without5051 = out.gridRepeated56Without5051 || e.repeated56Without5051;
    appendUnique(out.evidence, e.evidence);
}

bool hasAnyGridReferenceSequence(const ProtocolEvidence& e)
{
    return e.gridAuthComplete || e.gridSequence5051Seen || e.gridSequence5253Seen ||
           e.gridSequence5455Seen || e.gridSequence6061Seen;
}

void countIec104(ProtocolEvidence& out, const QList<Iec104Frame>& frames)
{
    for (const Iec104Frame& f : frames) {
        if (!f.valid)
            continue;
        ++out.iec104Frames;
        switch (f.kind) {
        case Iec104FrameKind::I: ++out.iec104IFrames; out.responseExpected=true; break;
        case Iec104FrameKind::S: ++out.iec104SFrames; break;
        case Iec104FrameKind::U:
            ++out.iec104UFrames;
            if (f.uFunction == Iec104UFunction::StartDtAct) { out.iec104StartDtActSeen = true; out.responseExpected=true; }
            if (f.uFunction == Iec104UFunction::StartDtCon) out.iec104StartDtConSeen = true;
            if (f.uFunction == Iec104UFunction::TestFrAct) { out.iec104TestFrActSeen = true; out.responseExpected=true; }
            if (f.uFunction == Iec104UFunction::TestFrCon) out.iec104TestFrConSeen = true;
            if (f.uFunction == Iec104UFunction::StopDtAct) { out.iec104StopDtActSeen = true; out.responseExpected=true; }
            if (f.uFunction == Iec104UFunction::StopDtCon) out.iec104StopDtConSeen = true;
            break;
        default: break;
        }
        if (f.kind == Iec104FrameKind::I && f.typeId >= 0)
            appendUnique(out.evidence, {QStringLiteral("IEC104 I帧 TypeID=%1 COT=%2 CA=%3")
                                           .arg(f.typeId).arg(f.cot).arg(f.commonAddress)});
    }
}

quint64 validIec101Count(const QList<Iec101Frame>& frames)
{
    quint64 n = 0;
    for (const Iec101Frame& f : frames)
        if (f.valid) ++n;
    return n;
}
}

ProtocolEvidence ProtocolDiagnosis::analyzeTcpPayload(const QByteArray& payload)
{
    ProtocolEvidence out;
    if (payload.isEmpty()) {
        out.layers = buildLayers(out);
        return out;
    }

    const QList<GridSecurityFrame> gridFrames = scanGridFrames(payload);
    if (!gridFrames.isEmpty()) {
        out.gridFrames = quint64(gridFrames.size());
        out.evidence << QStringLiteral("TCP载荷中识别到 EB...D7 国网安全/加密封装帧: %1").arg(out.gridFrames);
        out.evidence << QStringLiteral("当前抓包只有字节流方向，无法仅凭加密封装推断其内部一定是IEC101或IEC104");
        out.encryptedContentVisible = false;
        out.layers = buildLayers(out);
        return out;
    }

    const QList<Iec101Frame> f101 = Iec101Analyzer::parseStream(payload);
    const quint64 valid101 = validIec101Count(f101);
    if (valid101 > 0) {
        out.protocol = BusinessProtocol::Iec101;
        out.iec101Frames = valid101;
        for(const Iec101Frame& f:f101){
            if(!f.valid)continue;
            const bool primary=(f.control&0x40)!=0;
            const int function=f.control&0x0F;
            // Primary requests except unconfirmed user data normally expect a secondary reply.
            if(primary && function!=4){out.responseExpected=true;break;}
        }
        out.evidence << QStringLiteral("识别到有效IEC101帧: %1").arg(valid101);
        out.layers = buildLayers(out);
        return out;
    }

    const QList<Iec104Frame> f104 = Iec104Analyzer::parseStream(payload);
    countIec104(out, f104);
    if (out.iec104Frames > 0) {
        out.protocol = BusinessProtocol::Iec104;
        out.evidence << QStringLiteral("识别到有效IEC104 APDU: %1").arg(out.iec104Frames);
        if (out.iec104StartDtActSeen) out.evidence << QStringLiteral("观察到 STARTDT act");
        if (out.iec104StartDtConSeen) out.evidence << QStringLiteral("观察到 STARTDT con");
    }

    out.layers = buildLayers(out);
    return out;
}

ProtocolEvidence ProtocolDiagnosis::analyzeSerialBytes(const QByteArray& bytes)
{
    // IEC101 and IEC104 are identified from their framing, not from the physical transport.
    // Serial mode merely changes where the bytes came from; it does not justify guessing a protocol.
    return analyzeTcpPayload(bytes);
}

ProtocolEvidence ProtocolDiagnosis::analyzeLogText(const QString& text)
{
    ProtocolEvidence out;
    GridSecurityAnalyzer analyzer;
    const QStringList lines = text.split('\n', Qt::SkipEmptyParts);
    for (const QString& line : lines) {
        const GridSecurityFrame frame = GridSecurityAnalyzer::parseHexLogLine(line);
        if (frame.valid)
            analyzer.consume(frame);
    }
    addGridEvidence(out, analyzer.evidence());
    if (out.gridFrames > 0) {
        out.encryptedContentVisible = false;
        out.evidence.prepend(QStringLiteral("日志中识别到国网安全/加密封装帧: %1").arg(out.gridFrames));
    }
    out.layers = buildLayers(out);
    return out;
}

void ProtocolDiagnosis::merge(ProtocolEvidence& total, const ProtocolEvidence& part)
{
    if (total.protocol == BusinessProtocol::Unknown)
        total.protocol = part.protocol;
    else if (part.protocol != BusinessProtocol::Unknown && total.protocol != part.protocol)
        total.protocol = BusinessProtocol::Unknown;

    total.encryptedContentVisible = total.encryptedContentVisible || part.encryptedContentVisible;
    total.gridFrames += part.gridFrames;
    total.gridAuthComplete = total.gridAuthComplete || part.gridAuthComplete;
    total.gridSequence5051Seen = total.gridSequence5051Seen || part.gridSequence5051Seen;
    total.gridSequence5253Seen = total.gridSequence5253Seen || part.gridSequence5253Seen;
    total.gridSequence5455Seen = total.gridSequence5455Seen || part.gridSequence5455Seen;
    total.gridSequence6061Seen = total.gridSequence6061Seen || part.gridSequence6061Seen;
    total.gridRepeated56Without5051 = total.gridRepeated56Without5051 || part.gridRepeated56Without5051;
    total.iec101Frames += part.iec101Frames;
    total.iec104Frames += part.iec104Frames;
    total.iec104IFrames += part.iec104IFrames;
    total.iec104SFrames += part.iec104SFrames;
    total.iec104UFrames += part.iec104UFrames;
    total.iec104StartDtActSeen = total.iec104StartDtActSeen || part.iec104StartDtActSeen;
    total.iec104StartDtConSeen = total.iec104StartDtConSeen || part.iec104StartDtConSeen;
    total.iec104TestFrActSeen = total.iec104TestFrActSeen || part.iec104TestFrActSeen;
    total.iec104TestFrConSeen = total.iec104TestFrConSeen || part.iec104TestFrConSeen;
    total.iec104StopDtActSeen = total.iec104StopDtActSeen || part.iec104StopDtActSeen;
    total.iec104StopDtConSeen = total.iec104StopDtConSeen || part.iec104StopDtConSeen;
    total.iec104SequenceGaps += part.iec104SequenceGaps;
    total.iec104DuplicateIFrames += part.iec104DuplicateIFrames;
    total.iec104OutstandingIFrames = qMax(total.iec104OutstandingIFrames,part.iec104OutstandingIFrames);
    total.responseExpected = total.responseExpected || part.responseExpected;
    appendUnique(total.evidence, part.evidence);
    total.layers = buildLayers(total);
}

QList<LayerDiagnosis> ProtocolDiagnosis::buildLayers(const ProtocolEvidence& e)
{
    QStringList ev = e.evidence;
    if (e.gridFrames > 0)
        appendUnique(ev, {QStringLiteral("国网安全/加密封装帧=%1").arg(e.gridFrames)});
    if (e.iec101Frames > 0)
        appendUnique(ev, {QStringLiteral("IEC101有效帧=%1").arg(e.iec101Frames)});
    if (e.iec104Frames > 0)
        appendUnique(ev, {QStringLiteral("IEC104帧=%1, I=%2, S=%3, U=%4")
                              .arg(e.iec104Frames).arg(e.iec104IFrames).arg(e.iec104SFrames).arg(e.iec104UFrames)});

    // 第6层统一定义为“业务数据”。国网安全/加密交互与IEC101/104
    // 都是业务数据的不同表现形式，不再拆成两个诊断层。
    if (e.gridRepeated56Without5051) {
        if (!ev.join('\n').contains(QStringLiteral("正常样本基线")))
            ev << QStringLiteral("主站重复下发0x56，当前窗口未形成正常样本基线0x50→0x51");
        const QString conclusion = (e.iec101Frames > 0 || e.iec104Frames > 0)
            ? QStringLiteral("业务数据存在异常：已识别101/104数据，但国网加密业务交互与当前现场正常样本基线不一致")
            : QStringLiteral("国网加密业务交互异常：当前交互与现场正常样本基线不一致");
        return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::Medium,
                          conclusion, ev,
                          {QStringLiteral("核对主站加密通信配置、终端/模块安全参数及当前业务阶段")})};
    }

    if (e.iec104Frames > 0) {
        if(e.iec104SequenceGaps>0)appendUnique(ev,{QStringLiteral("IEC104 I帧发送序号跳变=%1").arg(e.iec104SequenceGaps)});
        if(e.iec104DuplicateIFrames>0)appendUnique(ev,{QStringLiteral("IEC104 重复/回退I帧=%1").arg(e.iec104DuplicateIFrames)});
        if(e.iec104OutstandingIFrames>0)appendUnique(ev,{QStringLiteral("IEC104 最大未确认I帧估算=%1").arg(e.iec104OutstandingIFrames)});
        if(e.iec104SequenceGaps>0){
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::High,
                              QStringLiteral("IEC104业务序号存在跳变，可能有丢帧、重连边界或抓包缺口"),ev,
                              {QStringLiteral("结合TCP重传/抓包缺口和对端104日志核对N(S)/N(R)连续性")})};
        }
        if(e.iec104OutstandingIFrames>=12){
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::Medium,
                              QStringLiteral("IEC104存在较多未确认I帧，确认窗口可能阻塞"),ev,
                              {QStringLiteral("检查对端S帧/I帧确认N(R)、链路时延及104 K/W参数")})};
        }
        if(e.iec104StopDtActSeen && !e.iec104StopDtConSeen){
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::Medium,
                              QStringLiteral("IEC104停止数据传输握手未完整：已见STOPDT act，未见STOPDT con"),ev)};
        }
        if(e.iec104TestFrActSeen && !e.iec104TestFrConSeen){
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::Medium,
                              QStringLiteral("IEC104链路测试未完整：已见TESTFR act，未见TESTFR con"),ev)};
        }
        if (e.iec104StartDtActSeen && !e.iec104StartDtConSeen) {
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::High,
                              QStringLiteral("IEC104业务启动存在异常：已观察到 STARTDT act，但当前抓包窗口未观察到 STARTDT con"), ev,
                              {QStringLiteral("继续观察主站/终端104启动流程和对端应答")})};
        }
        if (e.iec104StartDtActSeen && e.iec104StartDtConSeen) {
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Normal, Confidence::High,
                              QStringLiteral("业务通信正常：已识别 IEC104 报文，STARTDT 启动确认完整，已进入正常数据传输流程"), ev)};
        }
        return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Normal, Confidence::High,
                          QStringLiteral("业务通信正常：已识别有效 IEC104 业务报文"), ev)};
    }

    if (e.iec101Frames > 0) {
        return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Normal, Confidence::High,
                          QStringLiteral("业务通信正常：已识别有效 IEC101 业务报文"), ev)};
    }

    if (e.gridFrames > 0) {
        if (hasAnyGridReferenceSequence(e)) {
            appendUnique(ev, {QStringLiteral("加密业务内容不可见时，不伪解码其内部IEC101/104")});
            return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Normal, Confidence::Medium,
                              QStringLiteral("国网加密业务交互正常：已观察到加密业务封装及符合现场正常样本的请求/应答过程；加密内容不可见时不推断内部一定为IEC101或IEC104"), ev)};
        }
        appendUnique(ev, {QStringLiteral("无密钥/明文时不能仅凭EB...D7确认内部IEC101或IEC104")});
        return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::Warning, Confidence::Low,
                          QStringLiteral("已检测到国网加密业务封装，但当前抓包窗口不足以确认完整请求/应答流程；无密钥或明文时不可确认内部为IEC101还是IEC104"), ev)};
    }

    return {makeLayer(QStringLiteral("BUSINESS_DATA"), LayerState::NotTested, Confidence::Low,
                      QStringLiteral("当前抓包窗口未识别到可确认的 IEC101/IEC104 或国网加密业务数据；可能尚未到业务周期或抓包范围不足"))};
}
