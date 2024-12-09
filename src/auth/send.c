#include "../utils/log.h"
#include "packet.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t BOARDCAST_ADDR[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t MULTICASR_ADDR[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

void send_start_packet(pcap_t *handle, const AuthService auth_service) {
  // Start Packet
  // Build
  EAPOLHeader eapol = {.type = EAPOL_TYPE_START};
  EthernetHeader eth = {.eapol = &eapol};
  memcpy(eth.dst_mac, BOARDCAST_ADDR, HARDWARE_ADDR_SIZE);
  memcpy(eth.src_mac, auth_service.host_addr, HARDWARE_ADDR_SIZE);

  uint8_t *packet_to_send = build_eapol_packet(eth, 0);
  // Send and Free
  pcap_sendpacket(handle, packet_to_send,
                  ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE);
  free(packet_to_send);
  // printf("[SNT] StartPacket has been sent\n");
  log_info("Start Packet Has been sent", NULL);
}

void send_first_identity_packet(const AuthService auth_service,
                                const EthernetHeader eth_from) {
  uint8_t *type_data_buffer;
  size_t offset =
      build_first_identity_type_data(&type_data_buffer, auth_service);
  EAPHeader eap_to = {
      .code = EAP_CODE_RESPONSE,
      .identifier = eth_from.eapol->eap->identifier,
      .length = EAP_HEADER_SIZE + sizeof(eap_to.data.type) + offset,
      .data.type = EAP_TYPE_IDENTITY,
      .data.type_data = type_data_buffer,
  };
  EAPOLHeader eapol = {
      .type = EAPOL_TYPE_EAP,
      .eap = &eap_to,
  };
  EthernetHeader eth = {.eapol = &eapol};
  memcpy(eth.dst_mac, eth_from.src_mac, HARDWARE_ADDR_SIZE);
  memcpy(eth.src_mac, auth_service.host_addr, HARDWARE_ADDR_SIZE);

  uint8_t *packet_to_send = build_eap_packet(eth);
  // Send and Free
  pcap_sendpacket(auth_service.handle, packet_to_send,
                  ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE + EAP_HEADER_SIZE +
                      offset + sizeof(eap_to.data.type));
  free(packet_to_send);
  free(type_data_buffer);
  // printf("[SNT] FirstIdentity has been sent\n");
  log_info("FirstIdentity Has been sent", NULL);
}

void send_identity_packet(AuthService auth_service,
                          const EthernetHeader eth_from) {
  uint8_t *type_data_buffer;
  size_t offset =
      build_md5otp_type_data(&type_data_buffer, auth_service, eth_from);
  EAPHeader eap_to = {
      .code = EAP_CODE_RESPONSE,
      .identifier = eth_from.eapol->eap->identifier,
      .length = EAP_HEADER_SIZE + sizeof(eap_to.data.type) + offset,
      .data.type = EAP_TYPE_MD5OTP,
      .data.type_data = type_data_buffer,
  };
  EAPOLHeader eapol = {
      .type = EAPOL_TYPE_EAP,
      .eap = &eap_to,
  };
  EthernetHeader eth = {.eapol = &eapol};
  memcpy(eth.dst_mac, eth_from.src_mac, HARDWARE_ADDR_SIZE);
  memcpy(eth.src_mac, auth_service.host_addr, HARDWARE_ADDR_SIZE);

  uint8_t *packet_to_send = build_eap_packet(eth);
  // Send and Free
  pcap_sendpacket(auth_service.handle, packet_to_send,
                  ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE + EAP_HEADER_SIZE +
                      offset + sizeof(eap_to.data.type));
  free(packet_to_send);
  free(type_data_buffer);
  // printf("[SNT] Identity(MD5OTP) has been sent\n");
  log_info("Identity Has been sent", NULL);
}

void send_logoff_packet(pcap_t *handle, const AuthService auth_service) {
  EAPOLHeader eap = {
      .type = EAPOL_TYPE_LOGOFF,
  };
  EthernetHeader eth = {.eapol = &eap};
  // memcpy(eth.dst_mac, eth_from.src_mac, HARDWARE_ADDR_SIZE);
  // TODO: Get server hardware address
  memcpy(eth.src_mac, auth_service.host_addr, HARDWARE_ADDR_SIZE);
}
