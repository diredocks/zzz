#include "packet.h"
#include "../utils/log.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// get_mac_addr
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

int get_mac_addr(const char *interface, uint8_t *mac_addr) {
  int sockfd;
  struct ifreq ifr;
  // Create a socket
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    return 1; // Socket error
  }
  // Copy the interface name into the ifreq structure
  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0'; // Ensure null-terminated
  // Get the MAC address using ioctl
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    memcpy(mac_addr, mac, HARDWARE_ADDR_SIZE);
  } else {
    return 2; // IOCTL error
  }
  return 0;
}

void initail_handler(u_char *auth_service, const struct pcap_pkthdr *header,
                     const u_char *packet) {
  pcap_t *handle = ((AuthService *)auth_service)->handle;
  EAPHeader eap;
  EAPOLHeader eapol;
  EthernetHeader eth;
  parse_packet(packet, &eth, &eapol, &eap);

  if (eth.eapol != NULL && eapol.eap != NULL && eap.code == EAP_CODE_REQUESTS &&
      eap.data.type == EAP_TYPE_IDENTITY) { // eap packet
    eap_packet_printer(eap);
    memcpy(((AuthService *)auth_service)->server_addr, eth.src_mac,
           HARDWARE_ADDR_SIZE);
    // set handle filter to make client
    // proceed packets to device only
    struct bpf_program filter;
    char filter_str[128];
    sprintf(filter_str,
            "ether src " HARDWARE_ADDR_STR " and (ether dst " HARDWARE_ADDR_STR
            " or ether dst " HARDWARE_ADDR_STR ") and ether proto 0x888E",
            HARDWARE_ADDR_FMT(eth.src_mac), HARDWARE_ADDR_FMT(eth.dst_mac),
            HARDWARE_ADDR_FMT(MULTICASR_ADDR));
    pcap_compile((pcap_t *)handle, &filter, filter_str, 1, 0);
    pcap_setfilter((pcap_t *)handle, &filter);
    pcap_freecode(&filter);

    log_info("BPF Filter has been set", NULL);
    // Send FirstIdentity
    send_first_identity_packet(*(AuthService *)auth_service, eth);
    pcap_breakloop((pcap_t *)handle);
  }
}

// Initialize Handle:
void initialize_handle(AuthService *auth_service) {
  pcap_t *handle = auth_service->handle;
  // Send Start
  send_start_packet(handle, *auth_service);
  // Wait for Request, Set Filter
  pcap_loop(handle, -1, initail_handler, (u_char *)auth_service);
}
