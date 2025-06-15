#ifndef CONF_H
#define CONF_H

struct Config {
  const char *username;
  const char *password;
  const char *device;
};

extern struct Config g_config;

void config_init(const char *path);

#endif
