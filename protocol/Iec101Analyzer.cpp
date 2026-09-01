#include "Iec101Analyzer.h"

namespace {
quint8 checksum(const QByteArray& bytes, int start, int length)
{
    quint32 sum = 0;
    for (int i = 0; i < length; ++i)
        sum += quint8(bytes.at(start + i));
    return quint8(sum & 0xff);
}

Iec101Frame invalidFrame(const QString& error, const QByteArray& raw)
{
    Iec101Frame frame;
    frame.error = error;
    frame.raw = raw;
    return frame;
}
}

QList<Iec101Frame> Iec101Analyzer::parseStream(const QByteArray& bytes, int linkAddressLength)
{
    QList<Iec101Frame> out;
    if (linkAddressLength < 0) {
        out.append(invalidFrame(QStringLiteral("IEC101 invalid link address length"), bytes));
        return out;
    }

    int pos = 0;
    while (pos < bytes.size()) {
        const quint8 start = quint8(bytes.at(pos));
        if (start == 0x10) {
            const int total = 4 + linkAddressLength;
            if (bytes.size() - pos < total) {
                out.append(invalidFrame(QStringLiteral("IEC101 truncated fixed frame"), bytes.mid(pos)));
                break;
            }
            const QByteArray raw = bytes.mid(pos, total);
            if (quint8(raw.at(total - 1)) != 0x16) {
                out.append(invalidFrame(QStringLiteral("IEC101 fixed frame missing end byte"), raw));
                pos += total;
                continue;
            }
            const int protectedLength = 1 + linkAddressLength;
            const quint8 expected = checksum(raw, 1, protectedLength);
            const quint8 actual = quint8(raw.at(1 + protectedLength));
            if (expected != actual) {
                out.append(invalidFrame(QStringLiteral("IEC101 fixed frame checksum mismatch"), raw));
                pos += total;
                continue;
            }
            Iec101Frame frame;
            frame.valid = true;
            frame.kind = Iec101FrameKind::Fixed;
            frame.control = quint8(raw.at(1));
            frame.raw = raw;
            out.append(frame);
            pos += total;
            continue;
        }

        if (start == 0x68) {
            if (bytes.size() - pos < 4) {
                out.append(invalidFrame(QStringLiteral("IEC101 truncated variable frame header"), bytes.mid(pos)));
                break;
            }
            const int l1 = quint8(bytes.at(pos + 1));
            const int l2 = quint8(bytes.at(pos + 2));
            if (l1 != l2) {
                out.append(invalidFrame(QStringLiteral("IEC101 variable frame length bytes mismatch"), bytes.mid(pos)));
                break;
            }
            if (quint8(bytes.at(pos + 3)) != 0x68) {
                out.append(invalidFrame(QStringLiteral("IEC101 variable frame missing repeated start"), bytes.mid(pos, 4)));
                pos += 4;
                continue;
            }
            const int total = l1 + 6;
            if (l1 < 1 + linkAddressLength || bytes.size() - pos < total) {
                out.append(invalidFrame(QStringLiteral("IEC101 variable frame declared length exceeds available bytes"), bytes.mid(pos)));
                break;
            }
            const QByteArray raw = bytes.mid(pos, total);
            if (quint8(raw.at(total - 1)) != 0x16) {
                out.append(invalidFrame(QStringLiteral("IEC101 variable frame missing end byte"), raw));
                pos += total;
                continue;
            }
            const quint8 expected = checksum(raw, 4, l1);
            const quint8 actual = quint8(raw.at(4 + l1));
            if (expected != actual) {
                out.append(invalidFrame(QStringLiteral("IEC101 variable frame checksum mismatch"), raw));
                pos += total;
                continue;
            }

            Iec101Frame frame;
            frame.valid = true;
            frame.kind = Iec101FrameKind::Variable;
            frame.control = quint8(raw.at(4));
            const int asduOffset = 5 + linkAddressLength;
            const int asduLength = l1 - 1 - linkAddressLength;
            if (asduLength >= 1)
                frame.typeId = quint8(raw.at(asduOffset));
            // COT/common-address sizes are configurable in IEC101. Without those
            // parameters we deliberately leave cot/commonAddress unknown.
            frame.raw = raw;
            out.append(frame);
            pos += total;
            continue;
        }

        const int next10 = bytes.indexOf(char(0x10), pos + 1);
        const int next68 = bytes.indexOf(char(0x68), pos + 1);
        int next = -1;
        if (next10 >= 0 && next68 >= 0) next = qMin(next10, next68);
        else next = qMax(next10, next68);
        out.append(invalidFrame(QStringLiteral("IEC101 start byte not found at offset %1").arg(pos),
                                next < 0 ? bytes.mid(pos) : bytes.mid(pos, next - pos)));
        if (next < 0)
            break;
        pos = next;
    }
    return out;
}
