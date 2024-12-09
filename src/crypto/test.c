#include "crypto.h"
#include <stdint.h>
#include <stdio.h>

#define PRTARY(arr, size)                                                      \
  do {                                                                         \
    for (size_t i = 0; i < (size); i++) {                                      \
      printf("%02X ", (arr)[i]);                                               \
    }                                                                          \
    printf("\n");                                                              \
  } while (0)

int crypto_test(void) {
  uint8_t client_buffer[VERSION_BUFFER_SIZE];
  encrypted_client_version(client_buffer);
  PRTARY(client_buffer, VERSION_BUFFER_SIZE);
  uint8_t windows_buffer[VERSION_BUFFER_SIZE];
  encrypted_windows_version(windows_buffer);
  PRTARY(windows_buffer, VERSION_BUFFER_SIZE);
  uint8_t based_buffer[base64_encoded_length(VERSION_BUFFER_SIZE)];
  based_encrypted_client_version(based_buffer);
  printf("%s\n", based_buffer);
  PRTARY(based_buffer, base64_encoded_length(VERSION_BUFFER_SIZE));
  return 0;
}
