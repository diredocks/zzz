#include "packet/util.h"
#include "utils/common.h"
#include <string.h>

Result append_to_packet(Packet *packet, const uint8_t *data, size_t len) {
  if (packet->actual_len + len > packet->buffer_len) {
    return FAIL;
  }

  memcpy(packet->content, data, len);
  packet->actual_len += len;
  return SUCC;
}
