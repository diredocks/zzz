#include "crypto/crypto.h"
#include "crypto/md5.h"
#include "packet/packet.h"
#include "utils/config.h"
#include "utils/device.h"
#include "utils/log.h"

#include <stdlib.h>
#include <string.h>

#define APPEND_TO_BUFFER(buf, offset, data, len)                               \
  do {                                                                         \
    memcpy((buf) + *(offset), (data), (len));                                  \
    *(offset) += (len);                                                        \
  } while (0)

static struct Packet *make_base_packet(const struct Packet *pkt,
                                       uint8_t eapol_type, uint8_t eap_code,
                                       uint8_t eap_type, size_t payload_len) {
  size_t total_len = sizeof(struct Packet) + payload_len;
  struct Packet *packet = calloc(1, total_len);
  if (!packet)
    return NULL;

  memcpy(packet, &g_default_packet, sizeof(struct Packet));
  packet->eapol_type = eapol_type;
  packet->eap_code = eap_code;
  packet->eap_type = eap_type;
  packet->eap_id = pkt->eap_id;

  uint16_t eap_len = EAP_HEADER_SIZE + sizeof(packet->eap_type) + payload_len;
  packet->eap_length = htons(eap_len);
  packet->eapol_length = htons(eap_len);

  return packet;
}

void send_start_packet() {
  struct Packet packet = g_default_packet;
  packet.eapol_type = EAPOL_TYPE_START;

  device_send_packet(g_device.handle, (uint8_t *)&packet,
                     ETHERNET_HEADER_SIZE + EAPOL_HEADER_SIZE);
  log_info("sent start packet", NULL);
}

void send_first_identity_packet(const struct Packet *pkt) {
  size_t offset = 0;
  size_t payload_len =
      sizeof(PAYLOAD_VERSION_HEADER) + BASE64_LENGTH(BUFFER_SIZE) +
      sizeof(PAYLOAD_PADDING_HEADER) + strlen(g_config.username);

  struct Packet *packet = make_base_packet(
      pkt, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, EAP_TYPE_IDENTITY, payload_len);
  if (!packet)
    return;

  uint8_t *buf = packet->eap_type_data;
  APPEND_TO_BUFFER(buf, &offset, PAYLOAD_VERSION_HEADER,
                   sizeof(PAYLOAD_VERSION_HEADER));
  APPEND_TO_BUFFER(buf, &offset, g_based_client_version,
                   BASE64_LENGTH(BUFFER_SIZE));
  APPEND_TO_BUFFER(buf, &offset, PAYLOAD_PADDING_HEADER,
                   sizeof(PAYLOAD_PADDING_HEADER));
  APPEND_TO_BUFFER(buf, &offset, g_config.username, strlen(g_config.username));

  device_send_packet(g_device.handle, (uint8_t *)packet,
                     sizeof(struct Packet) + payload_len);
  log_info("sent first identity packet", NULL);
  free(packet);
}

void send_md5otp_packet(const struct Packet *pkt) {
  size_t offset = 0;
  size_t username_len = strlen(g_config.username);
  size_t payload_len = sizeof(pkt->eap_id) + MD5_LENGTH + username_len;

  struct Packet *packet = make_base_packet(
      pkt, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, EAP_TYPE_MD5OTP, payload_len);
  if (!packet)
    return;

  uint8_t *buf = packet->eap_type_data;
  *buf = MD5_LENGTH;
  offset++;

  int md5_buf_offset = 0;
  size_t md5_buf_len = 1 + strlen(g_config.password) + MD5_LENGTH;
  uint8_t md5_buf[md5_buf_len];

  APPEND_TO_BUFFER(md5_buf, &md5_buf_offset, &pkt->eap_id, sizeof(pkt->eap_id));
  APPEND_TO_BUFFER(md5_buf, &md5_buf_offset, g_config.password,
                   strlen(g_config.password));
  APPEND_TO_BUFFER(md5_buf, &md5_buf_offset, pkt->eap_type_data + 1,
                   MD5_LENGTH);

  md5Buffer(md5_buf, md5_buf_len, buf + offset);
  offset += MD5_LENGTH;

  APPEND_TO_BUFFER(buf, &offset, g_config.username, username_len);

  device_send_packet(g_device.handle, (uint8_t *)packet,
                     sizeof(struct Packet) + payload_len);
  log_info("sent md5otp packet", NULL);
  free(packet);
}
