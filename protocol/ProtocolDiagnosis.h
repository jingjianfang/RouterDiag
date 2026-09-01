#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>
#include <QtGlobal>
#include "diagnostic/DiagnosticTypes.h"

enum class BusinessProtocol {
    Unknown,
    Iec101,
    Iec104,
    GridEncrypted101,
    GridEncrypted104
};

struct ProtocolEvidence {
    BusinessProtocol protocol = BusinessProtocol::Unknown;
    bool encryptedContentVisible = false;

    quint64 gridFrames = 0;
    bool gridAuthComplete = false;
    bool gridSequence5051Seen = false;
    bool gridSequence5253Seen = false;
    bool gridSequence5455Seen = false;
    bool gridSequence6061Seen = false;
    bool gridRepeated56Without5051 = false;

    quint64 iec101Frames = 0;
    quint64 iec104Frames = 0;
    quint64 iec104IFrames = 0;
    quint64 iec104SFrames = 0;
    quint64 iec104UFrames = 0;
    bool iec104StartDtActSeen = false;
    bool iec104StartDtConSeen = false;
    bool iec104TestFrActSeen = false;
    bool iec104TestFrConSeen = false;
    bool iec104StopDtActSeen = false;
    bool iec104StopDtConSeen = false;
    quint64 iec104SequenceGaps = 0;
    quint64 iec104DuplicateIFrames = 0;
    quint64 iec104OutstandingIFrames = 0;
    bool responseExpected = false; // 识别到协议语义上通常应得到对端应答的请求/激活帧

    QStringList evidence;
    QList<LayerDiagnosis> layers;
};

class ProtocolDiagnosis {
public:
    static ProtocolEvidence analyzeTcpPayload(const QByteArray& payload);
    static ProtocolEvidence analyzeSerialBytes(const QByteArray& bytes);
    static ProtocolEvidence analyzeLogText(const QString& text);
    static void merge(ProtocolEvidence& total, const ProtocolEvidence& part);
    static QList<LayerDiagnosis> buildLayers(const ProtocolEvidence& evidence);
};
