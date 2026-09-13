#include "utils/config.h"
#include "utils/common.h"
#include "utils/misc.h"

#include <ini.h>
#include <stdlib.h>
#include <string.h>

static AuthConfig g_auth_config = {0};
static AppConfig g_app_config = {0};

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

static Result config_handler(void *_user, const char *section, const char *name,
                             const char *value) {
  char *copy = strdup(value);
  if (!copy)
    return FAIL;
  unescape_string(copy);

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
  if (MATCH("auth", "username")) {
    g_auth_config.username = copy;
  } else if (MATCH("auth", "password")) {
    g_auth_config.password = copy;
  } else if (MATCH("app", "interface")) {
    g_app_config.interface = copy;
  } else {
    free(copy);
    return FAIL; // unknown section / key
  }

  return SUCC;
}

Result config_init(const char *path) {
  if (ini_parse(path, config_handler, NULL) < 0) {
    return FAIL; // failed to parse config
  }

  if (g_auth_config.username == NULL || g_auth_config.password == NULL ||
      g_app_config.interface == NULL) {
    return FAIL; // not all required fields are set
  }

  return SUCC;
}

void config_free() {
  free_ptr(&g_auth_config.username);
  free_ptr(&g_auth_config.password);
  free_ptr(&g_app_config.interface);
}

AuthConfig *config_auth_get() { return &g_auth_config; }
AppConfig *config_app_get() { return &g_app_config; }
