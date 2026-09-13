#ifndef ZZZ_PACKET_H
#define ZZZ_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define ETHERNET_MAX_SIZE 1512
#define ETH_P_PAE 0x888e

typedef enum _eap_code {
  EAP_REQUEST = 1,
  EAP_RESPONSE,
  EAP_SUCCESS,
  EAP_FAILURE,
  EAP_H3C = 0x0a
} EapCode;

typedef enum _eapol_type {
  EAPOL_EAP = 0,
  EAPOL_START,
  EAPOL_LOGOFF,
} EapolType;

typedef enum _eap_type {
  EAP_IDENTITY = 1,
  EAP_MD5_CHALLENGE = 4,
  EAP_KICKOFF = 8,
  EAP_MD5_FAILURE = 9,
} EapType;

typedef struct _ethernet_header {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint8_t protocol[2];
} EthernetHeader;

typedef struct _eapol_header {
  uint8_t ver[1];
  uint8_t type[1];
  uint8_t len[2]; // 802.1Q will be preserved
} EapolHeader;

typedef struct _eap_header {
  uint8_t code[1];
  uint8_t id[1];
  uint8_t len[2];
  uint8_t type[1];
} EapHeader;

typedef struct _packet_header {
  EthernetHeader eth_hdr;
  EapolHeader eapol_hdr;
  EapHeader eap_hdr; // absent in EAPOL-Start and Logoff
} PacketHeader;      // skip the 8021x header manually

typedef struct _packet {
  size_t actual_len; // effective length of data in buffer
  size_t buffer_len; // current buffer length, do not write more than this
  union {
    uint8_t *content;
    PacketHeader *header;
  };
} Packet;

#endif // !ZZZ_PACKET_H
