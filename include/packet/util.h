#ifndef ZZZ_PACKET_UTIL_H
#define ZZZ_PACKET_UTIL_H

#include "packet/packet.h"
#include "utils/common.h"

Result append_to_packet(Packet *packet, const uint8_t *data, size_t len);

#endif // !ZZZ_PACKET_UTIL_H
