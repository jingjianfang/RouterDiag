#pragma once

#include "capture/TcpStreamReassembler.h"
#include <QtGlobal>
#include <QStringList>

struct Iec104SessionSummary {
    quint64 validFrames=0;
    bool startDtActSeen=false;
    bool startDtConSeen=false;
    bool stopDtActSeen=false;
    bool stopDtConSeen=false;
    bool testFrActSeen=false;
    bool testFrConSeen=false;
    quint64 sequenceGapCount=0;
    quint64 duplicateIFrameCount=0;
    quint64 outstandingIFrames=0;
    QStringList evidence;
};

class Iec104SessionAnalyzer {
public:
    static Iec104SessionSummary analyze(const QList<ReassembledTcpDirection>& directions);
};
