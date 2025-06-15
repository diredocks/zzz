#include "utils/config.h"
#include "utils/ini.h"
#include "utils/log.h"

#include <stdlib.h>
#include <string.h>

struct Config g_config;

static int hex_char_to_val(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static void unescape_string(char *str) {
  char *src = str, *dst = str;

  while (*src) {
    if (src[0] == '\\' && src[1] == 'x') {
      int hi = hex_char_to_val(src[2]);
      int lo = hex_char_to_val(src[3]);
      if (hi >= 0 && lo >= 0) {
        *dst++ = (char)((hi << 4) | lo);
        src += 4;
      } else {
        // invalid \x suffix
        *dst++ = *src++;
      }
    } else {
      *dst++ = *src++;
    }
  }

  *dst = '\0';
}

static int config_handler(void *user, const char *section, const char *name,
                          const char *value) {
#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  char *copy = strdup(value);
  if (!copy)
    return 0;
  unescape_string(copy);

  if (MATCH("auth", "username")) {
    g_config.username = copy;
  } else if (MATCH("auth", "password")) {
    g_config.password = copy;
  } else if (MATCH("auth", "device")) {
    g_config.device = copy;
  } else {
    free(copy);
    return 0; // unknown section/key
  }

  return 1;
}

void config_init(const char *path) {
  if (ini_parse(path, config_handler, &g_config) < 0) {
    log_error("can't parse config from given path", NULL);
    exit(EXIT_FAILURE);
  }
}
