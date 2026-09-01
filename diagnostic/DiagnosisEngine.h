#pragma once
#include "DiagnosticTypes.h"

class DiagnosisEngine {
public:
    static DiagnosisResult diagnose(const WanStatus& status);
    static QList<LayerDiagnosis> diagnoseWanLayers(const WanStatus& status);
};
