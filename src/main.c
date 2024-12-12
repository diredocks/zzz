#include "auth/packet.h"
#include "utils/log.h"
#include "utils/toml.h"
#include <pcap.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

AuthService auth_service;

void handle_signal(int sig) {
  if (auth_service.handle) {
    pcap_breakloop(auth_service.handle);
    printf("\r");
    send_logoff_packet(auth_service);
    log_info("Exiting d3x...", NULL);
  }
}

int main(void) {
  FILE *conf_file;
  char toml_err[200];
  conf_file = fopen("./config.toml", "r");
  if (!conf_file) {
    log_error("Error loading config.toml", NULL);
    return EXIT_FAILURE;
  }

  toml_table_t *conf = toml_parse_file(conf_file, toml_err, sizeof(toml_err));
  fclose(conf_file);
  if (!conf) {
    char err_msg[227];
    sprintf(err_msg, "Error loading config.toml: %s", toml_err);
    log_error(err_msg, NULL);
    return EXIT_FAILURE;
  }

  toml_table_t *toml_auth = toml_table_in(conf, "auth");
  if (!toml_auth) {
    log_error("Missing 'auth' table in config", NULL);
    toml_free(conf);
    return EXIT_FAILURE;
  }

  uint8_t device[30];
  toml_datum_t toml_device = toml_string_in(toml_auth, "device");
  if (!toml_device.ok) {
    log_error("Missing 'device' field in 'auth' table", NULL);
    toml_free(conf);
    return EXIT_FAILURE;
  }
  strncpy((char *)device, toml_device.u.s, sizeof(device) - 1);

  char err[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live((const char *)device, BUFSIZ, 0, 250, err);
  if (!handle) {
    log_error(err, NULL);
    free(toml_device.u.s);
    toml_free(conf);
    return EXIT_FAILURE;
  }

  int offline_flag = 1;
  auth_service.offline_flag = &offline_flag;
  auth_service.handle = handle;
  if (get_mac_addr((const char *)device, auth_service.host_addr)) {
    log_error("Error getting MAC address", NULL);
    return EXIT_FAILURE;
  }

  toml_datum_t toml_username = toml_string_in(toml_auth, "username");
  toml_datum_t toml_password = toml_string_in(toml_auth, "password");
  if (!toml_username.ok || !toml_password.ok) {
    log_error("Missing 'username' or 'password' in 'auth' table", NULL);
    pcap_close(handle);
    free(toml_username.u.s);
    free(toml_password.u.s);
    free(toml_device.u.s);
    toml_free(conf);
    return EXIT_FAILURE;
  }
  strncpy((char *)auth_service.username, toml_username.u.s,
          sizeof(auth_service.username) - 1);
  strncpy((char *)auth_service.password, toml_password.u.s,
          sizeof(auth_service.password) - 1);
  auth_service.username[sizeof(auth_service.username) - 1] = '\0';
  auth_service.password[sizeof(auth_service.password) - 1] = '\0';

  toml_datum_t toml_retry = toml_int_in(toml_auth, "retry");
  if (!toml_retry.ok) {
    log_error("Missing 'retry' in 'auth' table", NULL);
    pcap_close(handle);
    free(toml_username.u.s);
    free(toml_password.u.s);
    free(toml_device.u.s);
    toml_free(conf);
    return EXIT_FAILURE;
  }
  auth_service.retry = &toml_retry.u.i;

  free(toml_username.u.s);
  free(toml_password.u.s);
  free(toml_device.u.s);
  toml_free(conf);

  initialize_handle(&auth_service);

  signal(SIGINT, handle_signal);

  if (pcap_loop(handle, -1, packet_handler, (u_char *)&auth_service) == -1) {
    log_error(pcap_geterr(handle), NULL);
    pcap_close(handle);
    return EXIT_FAILURE;
  }

  // Close pcap handle
  pcap_close(handle);
  return EXIT_SUCCESS;
}
