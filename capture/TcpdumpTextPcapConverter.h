#pragma once

#include <QByteArray>
#include <QDate>
#include <QString>
#include <QStringList>
#include <QtGlobal>

struct TcpdumpTextConversionResult {
    QByteArray pcapData;
    int packetCount = 0;
    int truncatedPacketCount = 0;
    int skippedPacketCount = 0;
    quint32 linkType = 0;
    QDate sourceDate;
    QStringList warnings;
};

class TcpdumpTextPcapConverter {
public:
    static bool convert(const QByteArray& textBytes,
                        TcpdumpTextConversionResult* result,
                        QString* error = nullptr,
                        const QDate& fallbackDate = QDate());
};
