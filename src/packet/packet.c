#include "packet/packet.h"
#include "utils/device.h"

#include <string.h>

const uint8_t BOARDCAST_ADDR[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t MULTICASR_ADDR[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
const uint8_t PAYLOAD_VERSION_HEADER[2] = {0x06, 0x07};
const uint8_t PAYLOAD_PADDING_HEADER[2] = {0x20, 0x20};
const uint8_t PAYLOAD_IDENTITY_HEADER[2] = {0x16, 0x20};
const uint8_t PAYLOAD_IP_HEADER[2] = {0x15, 0x04};

struct Packet g_default_packet;

void packet_init_default() {
  g_default_packet = (struct Packet){
      .ether_type = htons(ETHERNET_TYPE_EAPOL),
      .version = EAPOL_VERSION,
  };
  memcpy(g_default_packet.dst_mac, BOARDCAST_ADDR, HARDWARE_ADDR_SIZE);
  memcpy(g_default_packet.src_mac, g_device.src_mac, HARDWARE_ADDR_SIZE);
}
