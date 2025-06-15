#include "crypto/crypto.h"
#include "crypto/base64.h"
#include "crypto/const.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

uint8_t g_win_version[BUFFER_SIZE];
uint8_t g_client_version[BUFFER_SIZE];
uint8_t g_based_client_version[BASE64_LENGTH(BUFFER_SIZE)];

void Xor(uint8_t *buffer, size_t buffer_len, const char *key, size_t key_len) {
  uint8_t i, j;
  for (i = 0; i < buffer_len; i++)
    buffer[i] ^= key[i % key_len];
  for (i = buffer_len - 1, j = 0; j < buffer_len; i--, j++)
    buffer[i] ^= key[j % key_len];
}

void crypto_init_win_version() {
  memcpy(g_win_version, WINDOWS_VERSION, strlen(WINDOWS_VERSION));
  Xor(g_win_version, BUFFER_SIZE, CLIENT_KEY, strlen(CLIENT_KEY));
}

void crypto_init_client_version() {
  // Generate a random_key
  uint32_t random_n = (uint32_t)time(NULL);
  char random_key[8 + 1];
  sprintf(random_key, "%08x", random_n);
  // xor first 16-bytes data with key generated
  memcpy(g_client_version, CLIENT_VERSION, strlen(CLIENT_VERSION));
  Xor(g_client_version, 16, random_key, strlen(random_key));
  // then append the random_n, which is 4-bytes
  *(uint32_t *)(g_client_version + 16) = htonl(random_n);
  // xor 20 bytes in total
  Xor(g_client_version, BUFFER_SIZE, CLIENT_KEY, strlen(CLIENT_KEY));
}

void crypto_init_based_client_version() {
  memcpy(g_based_client_version, g_client_version,
         BUFFER_SIZE); // only after client_version is initialized
  base64_encode(g_based_client_version, BUFFER_SIZE,
                BASE64_LENGTH(BUFFER_SIZE));
}

void crypto_init() {
  crypto_init_win_version();
  crypto_init_client_version();
  crypto_init_based_client_version();
}
