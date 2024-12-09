#include "packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// NOTE: parse_ethernet_packet will parse packet chainly
void parse_ethernet_packet(const u_char *packet, EthernetHeader *eth) {
  // TODO: Check if is valid Ethernet Frame
  memcpy(eth->dst_mac, packet, HARDWARE_ADDR_SIZE);
  memcpy(eth->src_mac, packet + HARDWARE_ADDR_SIZE, HARDWARE_ADDR_SIZE);
  eth->ethertype = ntohs(*(uint16_t *)(packet + 2 * HARDWARE_ADDR_SIZE));
  if (eth->eapol != NULL && eth->ethertype == ETHERNET_TYPE_EAPOL) {
    parse_eapol_packet(packet + ETHERNET_HEADER_SIZE, eth->eapol);
  } else {
    eth->eapol = NULL;
  }
}

void parse_eapol_packet(const u_char *packet, EAPOLHeader *eapol) {
  eapol->version = packet[0];
  eapol->type = packet[1];
  eapol->length = ntohs(*(uint16_t *)(packet + 2));
  if (eapol->eap != NULL && eapol->type == EAPOL_TYPE_EAP) {
    parse_eap_packet(packet + EAPOL_HEADER_SIZE, eapol->eap);
  } else {
    eapol->eap = NULL;
  }
}

void parse_eap_packet(const u_char *packet, EAPHeader *eap) {
  eap->code = packet[0];
  eap->identifier = packet[1];
  eap->length = ntohs(*(uint16_t *)(packet + 2));
  if (eap->length > EAP_HEADER_SIZE) {
    // eap packet with type inside
    (eap->data).type = packet[4];
    size_t type_data_length = eap->length - EAP_HEADER_SIZE - 1;
    if (type_data_length > 0) {
      // eap packet with type_data inside
      (eap->data).type_data = malloc(type_data_length);
      memcpy((eap->data).type_data, packet + EAP_HEADER_SIZE + 1,
             type_data_length);
    } else {
      (eap->data).type_data = NULL;
    }
  } else {
    // eap packet without type, type_data inside
    (eap->data).type = 255; // TODO: Make eap.data.type 255 a marco or enum
    (eap->data).type_data = NULL;
  }
}

void parse_packet(const u_char *packet, EthernetHeader *eth, EAPOLHeader *eapol,
                  EAPHeader *eap) {
  eth->eapol = eapol;
  eapol->eap = eap;
  parse_ethernet_packet(packet, eth);
}
