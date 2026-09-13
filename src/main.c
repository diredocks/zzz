#include "interface.h"
#include "utils/common.h"
#include "utils/config.h"
#include "utils/log.h"
#include <stdlib.h>

int main(int argc, char *argv[]) {
  const char *path = argv[1];
  if (IS_FAIL(config_init(path))) {
    log_errorf("can't load config from given path %s", path);
    exit(EXIT_FAILURE);
  }
  if (IS_FAIL(interface_init())) {
    log_errorf("can't init interface");
    exit(EXIT_FAILURE);
  }
  config_free();
  interface_free();
}
