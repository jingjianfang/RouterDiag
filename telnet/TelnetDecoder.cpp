#include "TelnetDecoder.h"

namespace { constexpr quint8 IAC=255, DONT=254, DO=253, WONT=252, WILL=251, SB=250, SE=240, BINARY=0; }

TelnetDecodeResult TelnetDecoder::feed(const QByteArray& input)
{
    TelnetDecodeResult out;
    for (unsigned char c : input) {
        switch (m_state) {
        case State::Data:
            if (c == IAC) m_state = State::Iac; else out.payload.append(char(c));
            break;
        case State::Iac:
            if (c == IAC) { out.payload.append(char(IAC)); m_state = State::Data; }
            else if (c == WILL || c == WONT || c == DO || c == DONT) { m_negotiationCommand = c; m_state = State::Negotiation; }
            else if (c == SB) m_state = State::Subnegotiation;
            else m_state = State::Data;
            break;
        case State::Negotiation: {
            quint8 reply = 0;
            if (c == BINARY && m_negotiationCommand == WILL) reply = DO;
            else if (c == BINARY && m_negotiationCommand == DO) reply = WILL;
            else if (m_negotiationCommand == WILL || m_negotiationCommand == WONT) reply = DONT;
            else reply = WONT;
            out.replyBytes.append(char(IAC)); out.replyBytes.append(char(reply)); out.replyBytes.append(char(c));
            m_state = State::Data;
            break;
        }
        case State::Subnegotiation:
            if (c == IAC) m_state = State::SubnegIac;
            break;
        case State::SubnegIac:
            m_state = (c == SE) ? State::Data : State::Subnegotiation;
            break;
        }
    }
    return out;
}

void TelnetDecoder::reset(){ m_state=State::Data; m_negotiationCommand=0; }
