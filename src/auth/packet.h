#include <arpa/inet.h> // For ntohs and htons
#include <pcap/pcap.h>
#include <sys/types.h>
#ifndef D3XPACKET
#define D3XPACKET

#define HARDWARE_ADDR_SIZE 6
#define HARDWARE_ADDR_STR "%02x:%02x:%02x:%02x:%02x:%02x"
#define HARDWARE_ADDR_FMT(mac)                                                 \
  (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]

#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_TYPE_EAPOL 0x888E
#define ETHERNET_FRAME_MIN_SIZE 64
#define CRC_SIZE 4

#define EAPOL_HEADER_SIZE 4
#define EAPOL_VERSION 0x01

#define EAPOL_TYPE_EAP 0x00
#define EAPOL_TYPE_START 0x01
#define EAPOL_TYPE_LOGOFF 0x02

#define EAP_HEADER_SIZE 4
#define EAP_CODE_REQUESTS 0x01
#define EAP_CODE_RESPONSE 0x02
#define EAP_CODE_SUCCESS 0x03
#define EAP_CODE_FAILURE 0x04
#define EAP_CODE_H3C 0x0a
#define EAP_TYPE_IDENTITY 0x01
#define EAP_TYPE_MD5OTP 0x04

#define MD5_LENGTH 16

#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64

extern const uint8_t BOARDCAST_ADDR[];
extern const uint8_t MULTICASR_ADDR[];

typedef struct {
  uint8_t username[MAX_USERNAME_LEN];
  uint8_t password[MAX_PASSWORD_LEN];
  uint8_t server_addr[HARDWARE_ADDR_SIZE];
  uint8_t host_addr[HARDWARE_ADDR_SIZE];
  pcap_t *handle;
} AuthService;

typedef struct {
  uint8_t type;
  uint8_t *type_data;
} EAPData;

// Struct for EAP packet
typedef struct {
  uint8_t code;
  uint8_t identifier; // id
  uint16_t length;    // in network byte order
  EAPData data;
} EAPHeader;

// Struct for EAPOL packet
typedef struct {
  uint8_t version;
  uint8_t type;
  uint16_t length; // in network byte order
  EAPHeader *eap;
} EAPOLHeader;

// Struct for Ethernet header
typedef struct {
  uint8_t dst_mac[HARDWARE_ADDR_SIZE];
  uint8_t src_mac[HARDWARE_ADDR_SIZE];
  uint16_t ethertype;
  EAPOLHeader *eapol;
} EthernetHeader;

int get_mac_addr(const char *interface, uint8_t *mac_addr);
int send_packet(pcap_t *handle, uint8_t *packet, size_t length);

void initialize_handle(AuthService *auth_service); // NOTE: For consistency with
                                                   // pcap_loop callback binding

// Functions implemented in parser.c
void parse_eap_packet(const u_char *packet, EAPHeader *eap);
void parse_eapol_packet(const u_char *packet, EAPOLHeader *eapol);
void parse_ethernet_packet(const u_char *packet, EthernetHeader *eth);
void parse_packet(const u_char *packet, EthernetHeader *eth, EAPOLHeader *eapol,
                  EAPHeader *eap);
// Functions implemented in handler.c
void eapol_packet_printer(EAPOLHeader eapol);
void eap_packet_printer(const EAPHeader eap);
void eapol_packet_handler(const EAPOLHeader eapol);
void eap_packet_handler(AuthService auth_service, const EthernetHeader eth);
void initail_handler(u_char *auth_service, const struct pcap_pkthdr *header,
                     const u_char *packet);
void packet_handler(u_char *auth_service, const struct pcap_pkthdr *header,
                    const u_char *packet);
// Functions implemented in builder.c
uint8_t *build_eapol_packet(const EthernetHeader eth, int fixed_length);
uint8_t *build_eap_packet(const EthernetHeader eth);
size_t build_first_identity_type_data(uint8_t **buffer,
                                      const AuthService auth_service);
size_t build_md5otp_type_data(uint8_t **buffer, const AuthService auth_service,
                              const EthernetHeader eth_from);
// Functions implemented in send.c
void send_identity_packet(
    const AuthService auth_service,
    const EthernetHeader eth_from); // TODO: identity -> md5otp
void send_start_packet(const AuthService auth_service);
void send_first_identity_packet(const AuthService auth_service,
                                const EthernetHeader eth_from);
void send_logoff_packet(const AuthService auth_service);
#endif
