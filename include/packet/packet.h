#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define HARDWARE_ADDR_SIZE 6
#define HARDWARE_ADDR_STR "%02x:%02x:%02x:%02x:%02x:%02x"
#define HARDWARE_ADDR_FMT(mac)                                                 \
  (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]

#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_TYPE_EAPOL 0x888E
#define ETHERNET_FRAME_MIN_SIZE 64
#define CRC_SIZE 4

#define EAPOL_HEADER_SIZE 4
#define EAPOL_VERSION 0x01

#define EAPOL_TYPE_EAP 0x00
#define EAPOL_TYPE_START 0x01
#define EAPOL_TYPE_LOGOFF 0x02

#define EAP_HEADER_SIZE 4
#define EAP_CODE_REQUESTS 0x01
#define EAP_CODE_RESPONSE 0x02
#define EAP_CODE_SUCCESS 0x03
#define EAP_CODE_FAILURE 0x04
#define EAP_CODE_H3C 0x0a
#define EAP_TYPE_IDENTITY 0x01
#define EAP_TYPE_MD5OTP 0x04
#define EAP_TYPE_KICKOFF 0x08
#define EAP_TYPE_MD5_FAILURE 0x09

#define MD5_LENGTH 16

// defined in packet.c to avoid conflict
extern const uint8_t BOARDCAST_ADDR[];
extern const uint8_t MULTICASR_ADDR[];
extern const uint8_t PAYLOAD_VERSION_HEADER[2];
extern const uint8_t PAYLOAD_PADDING_HEADER[2];
extern const uint8_t PAYLOAD_IDENTITY_HEADER[2];
extern const uint8_t PAYLOAD_IP_HEADER[2];

struct Packet {
  // Ethernet
  uint8_t dst_mac[HARDWARE_ADDR_SIZE];
  uint8_t src_mac[HARDWARE_ADDR_SIZE];
  uint16_t ether_type;
  // EAPOL
  uint8_t version;
  uint8_t eapol_type;
  uint16_t eapol_length; // in network byte order
  // EAP
  uint8_t eap_code;
  uint8_t eap_id;
  uint16_t eap_length; // in network byte order
  // EAP Data
  uint8_t eap_type;
  uint8_t eap_type_data[];
} __attribute__((__packed__));

extern struct Packet g_default_packet;
void packet_init_default();

#endif // PACKET_H
