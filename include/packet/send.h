#ifndef PACKET_SEND_H
#define PACKET_SEND_H

#include "packet.h"

void send_start_packet();
void send_first_identity_packet(const struct Packet *pkt);
void send_md5otp_packet(const struct Packet *pkt);

#endif // PACKET_SEND_H
