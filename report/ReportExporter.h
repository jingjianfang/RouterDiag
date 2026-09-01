#pragma once
#include "diagnostic/DiagnosticTypes.h"
#include "protocol/ProtocolDiagnosis.h"

class ReportExporter {
public:
    static QString buildTextReport(const WanStatus&,const DiagnosisResult&);
    static QString buildFieldReport(const WanStatus&,const FieldDiagnosisReport&,const ProtocolEvidence&);
    static bool saveTextReport(const QString&,const WanStatus&,const DiagnosisResult&,QString* error=nullptr);
    static bool saveJsonReport(const QString&,const WanStatus&,const DiagnosisResult&,QString* error=nullptr);
};
