#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QtGlobal>

enum class Iec104FrameKind { Invalid, I, S, U };
enum class Iec104UFunction { None, StartDtAct, StartDtCon, StopDtAct, StopDtCon, TestFrAct, TestFrCon };

struct Iec104Frame {
    bool valid = false;
    QString error;
    Iec104FrameKind kind = Iec104FrameKind::Invalid;
    Iec104UFunction uFunction = Iec104UFunction::None;
    quint16 sendSequence = 0;
    quint16 receiveSequence = 0;
    int typeId = -1;
    int cot = -1;
    int commonAddress = -1;
    QByteArray raw;
};

class Iec104Analyzer {
public:
    static QList<Iec104Frame> parseStream(const QByteArray& payload);
};
