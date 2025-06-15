#include "auth.h"
#include "crypto/aes-md5.h"
#include "packet/packet.h"
#include "packet/send.h"
#include "utils/device.h"
#include "utils/log.h"

#include <string.h>

const struct Packet *g_pkt;
struct pcap_pkthdr *g_hdr;

void auth_handshake(void) {
  send_start_packet();

  int ret = pcap_next_ex(g_device.handle, &g_hdr, (const u_char **)&g_pkt);
  if (ret != 1) {
    log_error("failed to handshake with server", NULL);
    return;
  }

  memcpy(g_default_packet.dst_mac, g_pkt->src_mac, HARDWARE_ADDR_SIZE);

  char filter_str[128];
  sprintf(filter_str,
          "ether src " HARDWARE_ADDR_STR " and (ether dst " HARDWARE_ADDR_STR
          " or ether dst " HARDWARE_ADDR_STR ") and ether proto 0x888E",
          HARDWARE_ADDR_FMT(g_default_packet.dst_mac),
          HARDWARE_ADDR_FMT(g_default_packet.src_mac),
          HARDWARE_ADDR_FMT(MULTICASR_ADDR));
  device_set_filter(filter_str);

  send_first_identity_packet(g_pkt);
}

int auth_loop(void) {
  int ret = pcap_next_ex(g_device.handle, &g_hdr, (const u_char **)&g_pkt);
  if (ret != 1) {
    log_error("failed to get packet from server", NULL);
    return 1;
  }

  switch (g_pkt->eap_code) {

  case EAP_CODE_SUCCESS:
    log_info("auth success (^_^)", NULL);
    break;

  case EAP_CODE_FAILURE:
    log_error("auth failed (T_T)", NULL);
    break;

  case EAP_CODE_REQUESTS:
    log_info("server requesting...", "type", g_pkt->eap_type);
    break;

  case EAP_CODE_H3C:
    if (*(uint16_t *)(g_pkt->eap_type_data) == 0x352b) {
      aes_md5_set_response(g_pkt->eap_type_data + 2);
      log_info("integrity set", NULL);
    }
    break;

  default:
    log_warn("unknown eap", "code", g_pkt->eap_code);
    break;
  }

  // in case if there's an error
  uint8_t err_msg_size = g_pkt->eap_type_data[0];
  char err_msg[err_msg_size + 1];

  switch (g_pkt->eap_type) {

  case EAP_TYPE_IDENTITY:
    send_identity_packet(g_pkt);
    log_info("answered identity", NULL);
    break;

  case EAP_TYPE_MD5OTP:
    send_md5otp_packet(g_pkt);
    log_info("answered md5otp", NULL);
    break;

  case EAP_TYPE_MD5_FAILURE:
    if (err_msg_size > 0) {
      memcpy(err_msg, (const char *)(g_pkt->eap_type_data + 1), err_msg_size);
      err_msg[err_msg_size] = '\0';
      log_error(err_msg, NULL);
    }
    return 2;
    break;

  case EAP_TYPE_KICKOFF:
    log_error("server kickoff", NULL);
    // TODO: restart auth
    break;

  default:
    log_warn("unsupported eap", "type", g_pkt->eap_type);
    break;
  }

  return 0;
}
