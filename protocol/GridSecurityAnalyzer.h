#pragma once

#include "GridFrameTypes.h"

class GridSecurityAnalyzer {
public:
    static GridSecurityFrame parseRawFrame(const QByteArray& raw, GridDirection direction = GridDirection::Unknown);
    static GridSecurityFrame parseHexLogLine(const QString& line);
    void consume(const GridSecurityFrame& frame);
    GridSecurityEvidence evidence() const;
    void reset();

private:
    enum class AuthStage { None, Got20, Got21, Got22, Complete };
    void observePair(quint8 command, GridDirection direction);

    GridSecurityEvidence m_evidence;
    AuthStage m_authStage = AuthStage::None;
    bool m_waiting50 = false;
    bool m_waiting52 = false;
    bool m_waiting54 = false;
    bool m_waiting60 = false;
    quint64 m_master56Count = 0;
};
