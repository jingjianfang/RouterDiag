#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QtGlobal>

enum class Iec101FrameKind { Invalid, Fixed, Variable };

struct Iec101Frame {
    bool valid = false;
    QString error;
    Iec101FrameKind kind = Iec101FrameKind::Invalid;
    quint8 control = 0;
    int typeId = -1;
    int cot = -1;
    int commonAddress = -1;
    QByteArray raw;
};

class Iec101Analyzer {
public:
    static QList<Iec101Frame> parseStream(const QByteArray& bytes, int linkAddressLength = 1);
};
