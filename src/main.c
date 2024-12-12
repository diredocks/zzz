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

void print_help() {
  printf("d3x: 802.1x client with ease\n");
  printf("  --help            Display this help message\n");
  printf("  --config [path]   Specify the configuration file path\n");
  printf("  --version         Display the version information\n");
}

void print_version() {
  const char *colors[] = {"\033[31m", "\033[33m", "\033[32m",
                          "\033[36m", "\033[34m", "\033[35m"};
  const char *reset = "\033[0m";
  const char *version = "     3    \n"
                        " __|  \\ / \n"
                        "|<<|   <  "
                        "  802.1x client with ease\n"
                        "|__|  / \\ \n"
                        "\n"
                        "github.com/diredocks/d3x\n";

  for (int i = 0; version[i] != '\0'; i++) {
    printf("%s%c%s", colors[i % 6], version[i], reset);
  }
}

int main(int argc, char *argv[]) {
  char *config_path;

  if (argc < 2) {
    log_error("No arguments provided. Use --help for usage information", NULL);
    return 1;
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_help();
      return 0;
    } else if (strcmp(argv[i], "--config") == 0) {
      if (i + 1 < argc) {
        config_path = argv[i + 1];
        i++; // Skip the next argument as it's the config path
      } else {
        log_error("--config option requires a file path argument", NULL);
        return 1;
      }
    } else if (strcmp(argv[i], "--version") == 0) {
      print_version();
      return 0;
    } else {
      log_error("Unknown option. Use --help for usage information", NULL);
      return 1;
    }
  }

  FILE *conf_file;
  char toml_err[200];
  conf_file = fopen(config_path, "r");
  if (!conf_file) {
    log_error("Can't load config from give path", NULL);
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
