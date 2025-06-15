#ifndef CRYPTO_H
#define CRYPTO_H

#include "crypto/base64.h"

#include <stdint.h>

#define BUFFER_SIZE 20

extern uint8_t g_win_version[BUFFER_SIZE];
extern uint8_t g_client_version[BUFFER_SIZE];
extern uint8_t g_based_client_version[BASE64_LENGTH(BUFFER_SIZE)];

void crypto_init();

#endif // CRYPTO_H
