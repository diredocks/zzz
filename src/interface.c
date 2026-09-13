#include "interface.h"
#include "packet/packet.h"
#include "utils/common.h"
#include "utils/config.h"
#include "utils/log.h"

#include <stdlib.h>

// forward declaration for actual implementaion of interfaces
Interface *pcap_new();

static Interface *g_interface = NULL;

Result interface_init() {
  AppConfig *config = config_app_get();
  Interface *if_impl = interface_get();

  if (IS_FAIL(if_impl->set_ifname(if_impl, config->interface))) {
    return FAIL;
  }
  if (IS_FAIL(if_impl->setup(if_impl, ETH_P_PAE, 0, NULL))) {
    return FAIL;
  }
  if (IS_FAIL(if_impl->init(if_impl))) {
    return FAIL;
  }

  return SUCC;
}

Interface *interface_get() {
  if (g_interface == NULL) {
    g_interface = pcap_new(); // TODO: bpf / raw_socket

    if (g_interface == NULL) {
      log_errorf("failed to allocate memory for interface");
      exit(EXIT_FAILURE);
    }
  }

  return g_interface;
}

void interface_free() { g_interface->free(g_interface); }
