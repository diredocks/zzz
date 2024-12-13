#include "packet.h"
#include "../utils/log.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// get_mac_addr
#ifdef _WIN32
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib") // Link against iphlpapi.lib
#else
#include <net/if.h>
#include <sys/ioctl.h>
#endif

#define HARDWARE_ADDR_SIZE 6 // MAC address length

int get_mac_addr(const char *interface_name, uint8_t *mac_addr) {
#ifdef _WIN32
  // Windows-specific code using GetAdaptersInfo

  IP_ADAPTER_INFO adapter_info[16];
  DWORD buf_len = sizeof(adapter_info);
  DWORD status;

  // Check if interface_name is invalid
  size_t iname_len = strlen(interface_name);
  if (iname_len != 50) {
    return 3; // Invalid interface name
  }

  // Get network adapter information
  status = GetAdaptersInfo(adapter_info, &buf_len);
  if (status != ERROR_SUCCESS) {
    return 1; // Error retrieving adapter info
  }

  // Iterate through the adapter list
  IP_ADAPTER_INFO *adapter = adapter_info;
  while (adapter) {
    if (strcmp(adapter->AdapterName, interface_name + 12) == 0) {
      // Copy the MAC address into the mac_addr buffer
      memcpy(mac_addr, adapter->Address, HARDWARE_ADDR_SIZE);
      return 0; // Success
    }
    adapter = adapter->Next;
  }

  return 2; // Interface not found
#else
  // Linux-specific code using ioctl and SIOCGIFHWADDR
  int sockfd;
  struct ifreq ifr;

  // Create a socket
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    return 1; // Socket error
  }

  // Copy the interface name into the ifreq structure
  strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0'; // Ensure null-terminated

  // Get the MAC address using ioctl
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    memcpy(mac_addr, mac, HARDWARE_ADDR_SIZE);
  } else {
    return 2; // IOCTL error
  }

  close(sockfd); // Close the socket
  return 0;
#endif
}

int send_packet(pcap_t *handle, uint8_t *packet, size_t length) {
  size_t padded_length = length;

  if (length < ETHERNET_FRAME_MIN_SIZE - CRC_SIZE) {
    padded_length = ETHERNET_FRAME_MIN_SIZE - CRC_SIZE;
  }

  uint8_t *padded_packet = malloc(padded_length);
  if (!padded_packet) {
    log_error("Memory allocation failed for padding", NULL);
    exit(EXIT_FAILURE);
  }

  memcpy(padded_packet, packet, length);
  if (padded_length > length) {
    memset(padded_packet + length, 0, padded_length - length);
  }

  int result = pcap_sendpacket(handle, padded_packet, padded_length);

  free(padded_packet);
  if (result != 0) {
    log_error(pcap_geterr(handle), NULL);
    exit(EXIT_FAILURE); // Adapter Disconnected
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
  // Send Start
  send_start_packet(*auth_service);
  // Wait for Request, Set Filter
  pcap_loop(auth_service->handle, -1, initail_handler, (u_char *)auth_service);
}
