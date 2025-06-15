// less than 320k

#include "auth.h"
#include "crypto/crypto.h"
#include "packet/packet.h"
#include "utils/config.h"
#include "utils/device.h"
#include "utils/log.h"

#include <pcap/pcap.h>
#include <signal.h>

void sig_exit() {
  printf("\r");
  if (g_device.handle) {
    pcap_close(g_device.handle);
  }
  log_info("zzz... bye", NULL);
  exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    log_error("Usage: zzz [path_to_config]", NULL);
    exit(EXIT_FAILURE);
  }

  log_info("zzz - i'm sleepy", NULL);

  signal(SIGINT, sig_exit);
  config_init(argv[1]);
  device_init(g_config.device);
  packet_init_default();
  crypto_init();

  auth_handshake();
  while (auth_loop() == 0) {
  }
  sig_exit();

  return 0;
}
