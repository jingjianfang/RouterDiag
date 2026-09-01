#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QtGlobal>

enum class GridDirection {
    Unknown,
    MasterToModule,
    ModuleToTerminal,
    TerminalToModule,
    ModuleToMaster
};

struct GridSecurityFrame {
    bool valid = false;
    QString error;
    GridDirection direction = GridDirection::Unknown;
    quint8 control = 0;
    quint8 command = 0;
    QByteArray raw;
};

struct GridSecurityEvidence {
    quint64 totalFrames = 0;
    QHash<int, quint64> commandCounts;
    bool auth8020To8023Complete = false;
    bool sequence5051Seen = false;
    bool sequence5253Seen = false;
    bool sequence5455Seen = false;
    bool sequence6061Seen = false;
    bool repeated56Without5051 = false;
    QStringList evidence;
};
