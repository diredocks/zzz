#include "interface.h"
#include "packet/packet.h"
#include "utils/common.h"
#include "utils/misc.h"

#include <net/if.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct _pcap_priv {
  int promisc;
  char ifname[IFNAMSIZ];
  uint16_t protocol;
  uint8_t src_mac[6];
  pcap_t *dev;
  void (*handler)(Packet *packet);
} PcapPriv;

#define PRIV ((PcapPriv *)this->priv)

static Result setup(Interface *this, uint16_t protocol, int promisc,
                    uint8_t src_mac[6]) {
  PRIV->promisc = promisc;
  PRIV->protocol = protocol;
  if (src_mac != NULL) {
    memcpy(PRIV->src_mac, src_mac, 6);
  }
  return SUCC;
}

static Result init(Interface *this) {
  char err_buf[PCAP_ERRBUF_SIZE] = {0};
  PRIV->dev = pcap_open_live(PRIV->ifname, ETHERNET_MAX_SIZE, PRIV->promisc,
                             100, err_buf);
  if (PRIV->dev == NULL) {
    return FAIL;
  }

  char filter_str[30] = {0};
  struct bpf_program bpf;
  // TODO: src_mac filter
  sprintf(filter_str, "ether proto 0x%hx", PRIV->protocol);
  if (pcap_compile(PRIV->dev, &bpf, filter_str, 0, 0) < 0) {
    return FAIL;
  }

  if (pcap_setfilter(PRIV->dev, &bpf) < 0) {
    return FAIL;
  }

  return SUCC;
}

static void _free(Interface *this) {
  if (PRIV->dev)
    pcap_close(PRIV->dev);
  free_ptr(&this->priv);
  free_ptr(&this);
}

static Result set_ifname(Interface *this, const char *ifname) {
  strncpy(PRIV->ifname, ifname, IFNAMSIZ - 1);
  return SUCC;
}

static Result get_ifname(Interface *this, char *buf, int buf_len) {
  if (buf_len < strnlen(PRIV->ifname, IFNAMSIZ)) {
    return FAIL;
  }
  strncpy(buf, PRIV->ifname, buf_len);
  return SUCC;
}

static void pcap_packet_handler(uint8_t *vthis,
                                const struct pcap_pkthdr *pkthdr,
                                const uint8_t *content) {
  Interface *this = (Interface *)vthis;
  Packet packet;

  packet.buffer_len = packet.actual_len = pkthdr->caplen;
  packet.content = (uint8_t *)content;

  PRIV->handler(&packet);
}

static Result start_capture(Interface *this) {
  pcap_loop(PRIV->dev, -1, pcap_packet_handler, (uint8_t *)this);
  return SUCC;
}

static Result stop_capture(Interface *this) {
  if (PRIV->dev) {
    pcap_breakloop(PRIV->dev);
    return SUCC;
  }
  return FAIL;
}

static Result send_packet(Interface *this, Packet *packet) {
  if (!PRIV->dev ||
      pcap_sendpacket(PRIV->dev, packet->content, packet->actual_len) < 0) {
    return FAIL;
  }
  return SUCC;
}

static void set_packet_handler(Interface *this,
                               void (*handler)(Packet *packet)) {
  PRIV->handler = handler;
}

Interface *pcap_new() {
  Interface *this = calloc(1, sizeof(Interface));
  if (this == NULL) {
    return NULL;
  }

  PcapPriv *priv = calloc(1, sizeof(PcapPriv));
  if (this == NULL) {
    free_ptr(&this);
    return NULL;
  }

  this->priv = priv;
  this->setup = setup;
  this->init = init;
  this->free = _free;
  this->set_ifname = set_ifname;
  this->get_ifname = get_ifname;
  this->start_capture = start_capture;
  this->stop_capture = stop_capture;
  this->send_packet = send_packet;
  this->set_packet_handler = set_packet_handler;

  return this;
}
