#ifndef ZZZ_CONF_H
#define ZZZ_CONF_H

#include "utils/common.h"

typedef struct _auth_config {
  char *username;
  char *password;
} AuthConfig;

typedef struct _app_config {
  char *interface;
} AppConfig;

Result config_init(const char *path);
void config_free();

AuthConfig *config_auth_get();
AppConfig *config_app_get();

#endif // !ZZZ_CONF_H
