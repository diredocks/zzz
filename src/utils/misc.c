#include "utils/misc.h"

#include <stdlib.h>

void free_ptr(void *pptr) {
  void **ptr = pptr;
  if (ptr == NULL || *ptr == NULL)
    return;
  free(*ptr);
  *ptr = NULL;
}
