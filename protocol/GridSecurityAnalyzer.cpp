#include "GridSecurityAnalyzer.h"

#include <QRegularExpression>

namespace {
GridDirection directionFromLine(const QString& line)
{
    if (line.contains(QString::fromUtf8("主站→模块")) || line.contains(QString::fromUtf8("主站->模块")))
        return GridDirection::MasterToModule;
    if (line.contains(QString::fromUtf8("模块→装置")) || line.contains(QString::fromUtf8("模块->装置")))
        return GridDirection::ModuleToTerminal;
    if (line.contains(QString::fromUtf8("装置→模块")) || line.contains(QString::fromUtf8("装置->模块")))
        return GridDirection::TerminalToModule;
    if (line.contains(QString::fromUtf8("模块→主站")) || line.contains(QString::fromUtf8("模块->主站")))
        return GridDirection::ModuleToMaster;
    return GridDirection::Unknown;
}

QString directionText(GridDirection direction)
{
    switch (direction) {
    case GridDirection::MasterToModule: return QString::fromUtf8("主站→模块");
    case GridDirection::ModuleToTerminal: return QString::fromUtf8("模块→装置");
    case GridDirection::TerminalToModule: return QString::fromUtf8("装置→模块");
    case GridDirection::ModuleToMaster: return QString::fromUtf8("模块→主站");
    default: return QString::fromUtf8("方向未知");
    }
}
}

GridSecurityFrame GridSecurityAnalyzer::parseRawFrame(const QByteArray& raw, GridDirection direction)
{
    GridSecurityFrame frame;
    frame.direction = direction;
    frame.raw = raw;

    if (raw.size() < 9) {
        frame.error = QStringLiteral("Grid frame too short");
        return frame;
    }
    const auto* b = reinterpret_cast<const uchar*>(raw.constData());
    if (b[0] != 0xeb || b[3] != 0xeb || b[raw.size() - 1] != 0xd7) {
        frame.error = QStringLiteral("Grid frame start/end marker mismatch");
        return frame;
    }
    const int declared = (int(b[1]) << 8) | int(b[2]);
    if (raw.size() != declared + 6) {
        frame.error = QStringLiteral("Grid frame length mismatch: declared %1, actual %2")
                          .arg(declared).arg(raw.size() - 6);
        return frame;
    }

    frame.control = b[5];
    frame.command = b[6];
    frame.valid = true;
    return frame;
}

GridSecurityFrame GridSecurityAnalyzer::parseHexLogLine(const QString& line)
{
    const GridDirection direction = directionFromLine(line);
    const int colon = line.lastIndexOf(':');
    const QString hexPart = colon >= 0 ? line.mid(colon + 1) : line;
    static const QRegularExpression hexByte(QStringLiteral("(?<![0-9A-Fa-f])([0-9A-Fa-f]{2})(?![0-9A-Fa-f])"));
    auto it = hexByte.globalMatch(hexPart);
    QByteArray raw;
    while (it.hasNext()) {
        const auto match = it.next();
        bool ok = false;
        const int value = match.captured(1).toInt(&ok, 16);
        if (ok)
            raw.append(char(value));
    }
    return parseRawFrame(raw, direction);
}

void GridSecurityAnalyzer::consume(const GridSecurityFrame& frame)
{
    if (!frame.valid)
        return;
    ++m_evidence.totalFrames;
    ++m_evidence.commandCounts[int(frame.command)];

    if (frame.direction == GridDirection::MasterToModule && frame.command == 0x56)
        ++m_master56Count;

    // Use origin directions for state transitions. Forwarded duplicates are
    // evidence that the module relayed the frame, but must not advance twice.
    if (frame.control == 0x80) {
        if (frame.direction == GridDirection::MasterToModule && frame.command == 0x20)
            m_authStage = AuthStage::Got20;
        else if (frame.direction == GridDirection::TerminalToModule && frame.command == 0x21 && m_authStage == AuthStage::Got20)
            m_authStage = AuthStage::Got21;
        else if (frame.direction == GridDirection::MasterToModule && frame.command == 0x22 && m_authStage == AuthStage::Got21)
            m_authStage = AuthStage::Got22;
        else if (frame.direction == GridDirection::TerminalToModule && frame.command == 0x23 && m_authStage == AuthStage::Got22) {
            m_authStage = AuthStage::Complete;
            m_evidence.auth8020To8023Complete = true;
        }
    }

    observePair(frame.command, frame.direction);

    if (m_evidence.auth8020To8023Complete &&
        !m_evidence.evidence.contains(QString::fromUtf8("观察到正常样本基线 80 20→80 21→80 22→80 23 完整交互"))) {
        m_evidence.evidence << QString::fromUtf8("观察到正常样本基线 80 20→80 21→80 22→80 23 完整交互");
    }
    m_evidence.repeated56Without5051 = m_master56Count >= 3 && !m_evidence.sequence5051Seen;
    if (m_evidence.repeated56Without5051) {
        const QString text = QString::fromUtf8("主站重复下发 0x56，当前观察窗口未形成正常样本基线 0x50→0x51");
        if (!m_evidence.evidence.contains(text))
            m_evidence.evidence << text;
    }
}

void GridSecurityAnalyzer::observePair(quint8 command, GridDirection direction)
{
    if (direction == GridDirection::MasterToModule) {
        if (command == 0x50) m_waiting50 = true;
        else if (command == 0x52) m_waiting52 = true;
        else if (command == 0x54) m_waiting54 = true;
        else if (command == 0x60) m_waiting60 = true;
        return;
    }
    if (direction != GridDirection::TerminalToModule)
        return;

    auto record = [this](bool& waiting, bool& seen, quint8 request, quint8 response) {
        if (!waiting)
            return;
        waiting = false;
        seen = true;
        m_evidence.evidence << QString::fromUtf8("观察到正常样本基线 0x%1→0x%2")
                                   .arg(request, 2, 16, QLatin1Char('0'))
                                   .arg(response, 2, 16, QLatin1Char('0'));
    };

    if (command == 0x51) record(m_waiting50, m_evidence.sequence5051Seen, 0x50, 0x51);
    else if (command == 0x53) record(m_waiting52, m_evidence.sequence5253Seen, 0x52, 0x53);
    else if (command == 0x55) record(m_waiting54, m_evidence.sequence5455Seen, 0x54, 0x55);
    else if (command == 0x61) record(m_waiting60, m_evidence.sequence6061Seen, 0x60, 0x61);
}

GridSecurityEvidence GridSecurityAnalyzer::evidence() const
{
    return m_evidence;
}

void GridSecurityAnalyzer::reset()
{
    m_evidence = GridSecurityEvidence{};
    m_authStage = AuthStage::None;
    m_waiting50 = false;
    m_waiting52 = false;
    m_waiting54 = false;
    m_waiting60 = false;
    m_master56Count = 0;
}
