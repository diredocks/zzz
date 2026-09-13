#ifndef ZZZ_INTERFACE_H
#define ZZZ_INTERFACE_H

#include "packet/packet.h"
#include "utils/common.h"

typedef struct _interface {
  Result (*setup)(struct _interface *this, uint16_t protocol, int promisc,
                  uint8_t src_mac[6]);
  Result (*init)(struct _interface *this);
  void (*free)(struct _interface *this);

  Result (*set_ifname)(struct _interface *this, const char *ifname);
  Result (*get_ifname)(struct _interface *this, char *buf, int buf_len);

  Result (*start_capture)(struct _interface *this);
  Result (*stop_capture)(struct _interface *this);

  Result (*send_packet)(struct _interface *this, Packet *packet);
  void (*set_packet_handler)(struct _interface *this,
                             void (*handler)(Packet *packet));

  void *priv; // for interface internal use only
} Interface;

Result interface_init();
Interface *interface_get();
void interface_free();

#endif // !ZZZ_INTERFACE_H
