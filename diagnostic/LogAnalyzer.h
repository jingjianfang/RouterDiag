#pragma once
#include "DiagnosticTypes.h"
#include "NvramSnapshotParser.h"
class LogAnalyzer {
public:
    static WanStatus analyze(const QString& text);
    static WanStatus analyzeNvramSnapshot(const NvramSnapshot& snapshot);
};
