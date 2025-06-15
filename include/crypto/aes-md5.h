#ifndef CRYPTO_AES_MD5_H
#define CRYPTO_AES_MD5_H

#include <stdint.h>

typedef struct {
  uint8_t offset;
  uint8_t length;
} DictQuery;

void aes_md5_set_response(const uint8_t *encrypted_data);
extern uint8_t g_aes_md5_response[32];

#endif
