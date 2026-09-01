#include "Iec104Analyzer.h"

namespace {
quint16 le16(const uchar* p)
{
    return quint16(p[0]) | (quint16(p[1]) << 8);
}

Iec104UFunction decodeUFunction(quint8 c)
{
    switch (c) {
    case 0x07: return Iec104UFunction::StartDtAct;
    case 0x0b: return Iec104UFunction::StartDtCon;
    case 0x13: return Iec104UFunction::StopDtAct;
    case 0x23: return Iec104UFunction::StopDtCon;
    case 0x43: return Iec104UFunction::TestFrAct;
    case 0x83: return Iec104UFunction::TestFrCon;
    default: return Iec104UFunction::None;
    }
}
}

QList<Iec104Frame> Iec104Analyzer::parseStream(const QByteArray& payload)
{
    QList<Iec104Frame> out;
    int pos = 0;
    while (pos < payload.size()) {
        if (quint8(payload.at(pos)) != 0x68) {
            const int next = payload.indexOf(char(0x68), pos + 1);
            Iec104Frame invalid;
            invalid.error = QStringLiteral("IEC104 start byte 0x68 not found at offset %1").arg(pos);
            invalid.raw = next < 0 ? payload.mid(pos) : payload.mid(pos, next - pos);
            out.append(invalid);
            if (next < 0)
                break;
            pos = next;
            continue;
        }

        if (payload.size() - pos < 2) {
            Iec104Frame invalid;
            invalid.error = QStringLiteral("IEC104 truncated length field");
            invalid.raw = payload.mid(pos);
            out.append(invalid);
            break;
        }

        const int declared = quint8(payload.at(pos + 1));
        const int total = declared + 2;
        if (declared < 4) {
            Iec104Frame invalid;
            invalid.error = QStringLiteral("IEC104 invalid length %1").arg(declared);
            invalid.raw = payload.mid(pos, qMin(total, payload.size() - pos));
            out.append(invalid);
            pos += qMax(2, total);
            continue;
        }
        if (payload.size() - pos < total) {
            Iec104Frame invalid;
            invalid.error = QStringLiteral("IEC104 declared length exceeds available bytes");
            invalid.raw = payload.mid(pos);
            out.append(invalid);
            break;
        }

        Iec104Frame frame;
        frame.raw = payload.mid(pos, total);
        const auto* b = reinterpret_cast<const uchar*>(frame.raw.constData());
        const quint8 c0 = b[2];
        const quint8 c1 = b[3];
        const quint8 c2 = b[4];
        const quint8 c3 = b[5];

        if ((c0 & 0x01) == 0) {
            frame.kind = Iec104FrameKind::I;
            frame.sendSequence = quint16((quint16(c0) | (quint16(c1) << 8)) >> 1);
            frame.receiveSequence = quint16((quint16(c2) | (quint16(c3) << 8)) >> 1);
            const int asduLength = declared - 4;
            if (asduLength >= 1)
                frame.typeId = b[6];
            if (asduLength >= 6) {
                frame.cot = b[8] & 0x3f;
                frame.commonAddress = int(le16(b + 10));
            }
        } else if ((c0 & 0x03) == 0x01) {
            frame.kind = Iec104FrameKind::S;
            frame.receiveSequence = quint16((quint16(c2) | (quint16(c3) << 8)) >> 1);
        } else if ((c0 & 0x03) == 0x03) {
            frame.kind = Iec104FrameKind::U;
            frame.uFunction = decodeUFunction(c0);
        } else {
            frame.error = QStringLiteral("IEC104 unsupported control field");
            out.append(frame);
            pos += total;
            continue;
        }

        frame.valid = true;
        out.append(frame);
        pos += total;
    }
    return out;
}
