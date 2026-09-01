#pragma once
#include "PcapTypes.h"
class PacketParser { public: static ParsedPacket parse(const PcapRecord& record, quint32 linkType); };
