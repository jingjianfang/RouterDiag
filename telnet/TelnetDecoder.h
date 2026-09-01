#pragma once
#include <QByteArray>

struct TelnetDecodeResult {
    QByteArray payload;
    QByteArray replyBytes;
};

class TelnetDecoder {
public:
    TelnetDecodeResult feed(const QByteArray& input);
    void reset();
private:
    enum class State { Data, Iac, Negotiation, Subnegotiation, SubnegIac };
    State m_state = State::Data;
    quint8 m_negotiationCommand = 0;
};
