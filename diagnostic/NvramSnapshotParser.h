#pragma once

#include <QByteArray>
#include <QMap>
#include <QString>

// Offline router configuration snapshot formats seen on Four-Faith field devices.
// Text is the output of `nvram show`; FourFaithBinary is the vendor export format
// beginning with "FOUR-FAITH:" followed by a format byte and length-prefixed records.
enum class NvramSnapshotFormat { Unknown, Text, FourFaithBinary };

struct NvramSnapshot {
    bool valid = false;
    NvramSnapshotFormat format = NvramSnapshotFormat::Unknown;
    int binaryVersion = -1;
    int recordCount = 0;
    QMap<QString,QString> values;
    QString error;

    QString value(const QString& key) const { return values.value(key); }
    bool contains(const QString& key) const { return values.contains(key); }
};

class NvramSnapshotParser {
public:
    static NvramSnapshot parse(const QByteArray& bytes);
    static NvramSnapshot parseText(const QString& text);
    static QString formatName(NvramSnapshotFormat format);
    static bool isSensitiveKey(const QString& key);
};
