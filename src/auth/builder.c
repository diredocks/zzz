#include "../crypto/crypto.h"
#include "packet.h"
#include <stdlib.h>
#include <string.h>

void append_to_buffer(uint8_t *dest, int *offset, const uint8_t *src,
                      size_t len) {
  memcpy(dest + *offset, src, len);
  *offset += len;
}

// NOTE: if linked to eap, you can turn fixed_length off
uint8_t *build_eapol_packet(const EthernetHeader eth, int fixed_length) {
  // WARN: eth must contain a eapol header!
  uint8_t *packet = malloc(ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE);
  int offset = 0;
  // Ethernet
  // Destination and Source MAC
  append_to_buffer(packet, &offset, eth.dst_mac, HARDWARE_ADDR_SIZE);
  append_to_buffer(packet, &offset, eth.src_mac, HARDWARE_ADDR_SIZE);
  // Packet Type
  *(uint16_t *)(packet + offset) = htons(ETHERNET_TYPE_EAPOL);
  offset += sizeof(eth.ethertype);
  // EAPOL
  // Version
  packet[offset] = EAPOL_VERSION;
  offset += sizeof((eth.eapol)->version);
  // Type
  append_to_buffer(packet, &offset, &((eth.eapol)->type),
                   sizeof((eth.eapol)->type));
  // Length
  if (fixed_length) {
    *(uint16_t *)(packet + offset) = htons((eth.eapol)->length);
  } else {
    if ((eth.eapol)->eap != NULL) {
      *(uint16_t *)(packet + offset) = htons((eth.eapol)->eap->length);
    } else {
      *(uint16_t *)(packet + offset) = 0x0000;
    }
  }
  offset += sizeof((eth.eapol)->length);
  return packet;
}

uint8_t *build_eap_packet(const EthernetHeader eth) {
  // WARN: eth must contain a eapol header with non-null pointer to eap header!
  size_t type_len = (eth.eapol->eap)->length - EAP_HEADER_SIZE;
  uint8_t *packet = malloc(ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE +
                           EAP_HEADER_SIZE + type_len);

  uint8_t *eapol_packet = build_eapol_packet(eth, 0);
  int offset = ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE;
  memcpy(packet, eapol_packet, offset);
  free(eapol_packet);

  // EAP
  // Code
  packet[offset] = eth.eapol->eap->code;
  offset += sizeof((eth.eapol->eap)->code);
  // ID
  packet[offset] = (eth.eapol->eap)->identifier;
  offset += sizeof((eth.eapol->eap)->identifier);
  // Length
  *(uint16_t *)(packet + offset) = htons((eth.eapol->eap)->length);
  offset += sizeof((eth.eapol->eap)->length);
  // Type
  if ((eth.eapol->eap)->length > EAP_HEADER_SIZE) {
    packet[offset] = (eth.eapol->eap)->data.type;
    offset += sizeof((eth.eapol->eap)->data.type);
    // Type Data
    if (type_len - sizeof((eth.eapol->eap)->data.type) > 0) {
      append_to_buffer(packet, &offset, (eth.eapol->eap)->data.type_data,
                       type_len - sizeof((eth.eapol->eap)->data.type));
    }
  }
  return packet;
}

size_t build_first_identity_type_data(uint8_t **buffer,
                                      const AuthService auth_service) {
  // FirstIdentity Packet
  // Build
  uint8_t version_header_buffer[] = {0x06, 0x07};
  size_t based_version_len = base64_encoded_length(VERSION_BUFFER_SIZE);
  uint8_t based_version_buffer[based_version_len];
  based_encrypted_client_version(based_version_buffer);

  size_t username_buffer_len = strlen((const char *)auth_service.username);
  uint8_t padding_buffer[] = {0x20, 0x20};

  int offset = 0;
  uint8_t *type_data_buffer =
      malloc(sizeof(version_header_buffer) + based_version_len +
             sizeof(padding_buffer) + username_buffer_len);

  append_to_buffer(type_data_buffer, &offset, version_header_buffer,
                   sizeof(version_header_buffer));
  append_to_buffer(type_data_buffer, &offset, based_version_buffer,
                   based_version_len);
  append_to_buffer(type_data_buffer, &offset, padding_buffer,
                   sizeof(padding_buffer));
  append_to_buffer(type_data_buffer, &offset, auth_service.username,
                   username_buffer_len);

  *buffer = type_data_buffer;
  return offset;
}

size_t build_md5otp_type_data(uint8_t **buffer, const AuthService auth_service,
                              const EthernetHeader eth_from) {
  // TODO: username, password
  // MD5Otp Packet
  size_t password_buffer_len = strlen((const char *)auth_service.password);
  size_t username_buffer_len = strlen((const char *)auth_service.username);

  size_t data_to_be_md5_buffer_len = sizeof(eth_from.eapol->eap->identifier) +
                                     password_buffer_len + MD5_LENGTH;
  uint8_t *data_to_be_md5_buffer = malloc(data_to_be_md5_buffer_len);
  int offset = 0;
  data_to_be_md5_buffer[offset] = eth_from.eapol->eap->identifier;
  offset += sizeof(eth_from.eapol->eap->identifier);
  append_to_buffer(data_to_be_md5_buffer, &offset, auth_service.password,
                   password_buffer_len);
  append_to_buffer(data_to_be_md5_buffer, &offset,
                   eth_from.eapol->eap->data.type_data + 1, MD5_LENGTH);

  uint8_t md5challange_data_buffer[MD5_LENGTH];
  md5_buffer(data_to_be_md5_buffer, data_to_be_md5_buffer_len,
             md5challange_data_buffer);
  free(data_to_be_md5_buffer);

  uint8_t *type_data_buffer =
      malloc(1 + sizeof(md5challange_data_buffer) + username_buffer_len);
  offset = 0;
  type_data_buffer[offset] = MD5_LENGTH;
  offset += 1;
  append_to_buffer(type_data_buffer, &offset, md5challange_data_buffer,
                   MD5_LENGTH);
  append_to_buffer(type_data_buffer, &offset, auth_service.username,
                   username_buffer_len);
  *buffer = type_data_buffer;
  return offset;
}
