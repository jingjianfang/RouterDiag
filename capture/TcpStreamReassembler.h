#pragma once

#include <QByteArray>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QHash>
#include "PcapTypes.h"

struct ReassembledTcpDirection {
    QString flowKey;
    QString sourceEndpoint;
    QString destinationEndpoint;
    QByteArray bytes;
    bool gapObserved = false;
};

class TcpStreamReassembler {
public:
    void reset();
    void consume(const ParsedPacket& packet);
    QList<ReassembledTcpDirection> directions() const;
    QByteArray bytesForPacketDirection(const ParsedPacket& packet) const;

private:
    struct DirectionState {
        bool initialized = false;
        quint32 nextSequence = 0;
        QByteArray bytes;
        QMap<quint32,QByteArray> pending;
        bool gapObserved = false;
    };
    struct FlowState {
        QString endpointA;
        QString endpointB;
        DirectionState aToB;
        DirectionState bToA;
    };

    static QString endpoint(const QString& ip,quint16 port);
    static QString flowKey(const ParsedPacket& packet);
    static void consumePayload(DirectionState& state,quint32 sequence,const QByteArray& payload);
    static void drainPending(DirectionState& state);

    QHash<QString,FlowState> m_flows;
};
