#include "utils/device.h"
#include "utils/log.h"

#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct Device g_device;

void device_send_packet(pcap_t *handle, uint8_t *packet, size_t length) {
  size_t padded_length = length;

  if (length < ETHERNET_FRAME_MIN_SIZE - CRC_SIZE) {
    padded_length = ETHERNET_FRAME_MIN_SIZE - CRC_SIZE;
  }

  uint8_t *padded_packet = calloc(1, padded_length);
  if (!padded_packet) {
    log_error("memory allocation failed for padding", NULL);
    exit(EXIT_FAILURE);
  }

  memcpy(padded_packet, packet, length);

  if (pcap_sendpacket(handle, padded_packet, padded_length) != 0) {
    log_error(pcap_geterr(handle), NULL);
    free(padded_packet);
    exit(EXIT_FAILURE);
  }

  free(padded_packet);
}

void device_set_hardware_addr(uint8_t *target_addr,
                              const char *interface_name) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    log_error("failed to create socket", NULL);
    exit(EXIT_FAILURE);
  }

  struct ifreq ifr;
  strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';

  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0) {
    log_error("failed to get hardware address", NULL);
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
  memcpy(target_addr, mac, HARDWARE_ADDR_SIZE);

  close(sockfd);
}

void device_set_filter(const char *filter_str) {
  struct bpf_program filter;
  pcap_compile(g_device.handle, &filter, filter_str, 1, 0);
  pcap_setfilter(g_device.handle, &filter);
  pcap_freecode(&filter);
}

void device_init(const char *interface_name) {
  char err[PCAP_ERRBUF_SIZE];
  g_device.handle = pcap_open_live(interface_name, BUFSIZ, 0, 250, err);
  if (!(g_device.handle)) {
    log_error(err, NULL);
    exit(EXIT_FAILURE);
  }

  device_set_filter("ether proto 0x888E");
  device_set_hardware_addr(g_device.src_mac, interface_name);
}
