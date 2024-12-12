#include "../utils/log.h"
#include "packet.h"
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void eapol_packet_printer(EAPOLHeader eapol) {
  log_info("EAPOL", "Type", eapol.type, "Version", eapol.version, "Length",
           eapol.length, NULL);
}

void eapol_packet_handler(EAPOLHeader eapol) { eapol_packet_printer(eapol); }

void eap_packet_printer(const EAPHeader eap) {
  if (eap.data.type != 255) { // TODO: Make eap.data.type 255 a marco or enum
    if (eap.data.type_data != NULL) {
      log_info("EAP", "Id", eap.identifier, "Code", eap.code, "Length",
               eap.length, "Type", eap.data.type, "TypeData[0]",
               eap.data.type_data[0], NULL);
    } else {
      log_info("EAP", "Id", eap.identifier, "Code", eap.code, "Length",
               eap.length, "Type", eap.data.type, NULL);
    }
  } else {
    log_info("EAP", "Id", eap.identifier, "Code", eap.code, "Length",
             eap.length);
  }
}

void eap_request_handler(AuthService auth_service, const EthernetHeader eth) {
  pcap_t *handle = auth_service.handle;
  switch (eth.eapol->eap->data.type) {
  case EAP_TYPE_MD5OTP:
    send_identity_packet(auth_service, eth);
    break;
  default:
    log_warn("Unknow EAP", "Id", eth.eapol->eap->identifier, "Type",
             eth.eapol->eap->data.type, NULL);
  }
}

void eap_packet_handler(AuthService auth_service, const EthernetHeader eth) {
  eap_packet_printer(*(eth.eapol->eap));
  switch (eth.eapol->eap->code) {
  case EAP_CODE_REQUESTS:
    eap_request_handler(auth_service, eth);
    break;
  case EAP_CODE_RESPONSE:
    break;
  case EAP_CODE_FAILURE:
    log_error("Login Failure", NULL);
    break;
  case EAP_CODE_SUCCESS:
    log_info("Login Successful", NULL);
    break;
  case EAP_CODE_H3C:
    break;
  default:
    log_warn("Unknow EAP", "Id", eth.eapol->eap->identifier, "Code",
             eth.eapol->eap->code, NULL);
  }
  if (eth.eapol->eap->data.type_data != NULL) {
    free(eth.eapol->eap->data.type_data);
  }
}

void packet_handler(u_char *auth_service, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  EAPHeader eap;
  EAPOLHeader eapol;
  EthernetHeader eth;
  parse_packet(packet, &eth, &eapol, &eap);

  if (eth.eapol != NULL && eapol.eap == NULL) { // eapol packet handler
    eapol_packet_handler(eapol);
  }
  if (eth.eapol != NULL && eapol.eap != NULL) { // eap packet handler
    eap_packet_handler(*(AuthService *)auth_service, eth);
  }
}
