#include "crypto.h"
#include "md5.h"
#include <arpa/inet.h> // For ntohs and htons
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char CLIENT_VERSION[] = "CH\x11V7.30-0601";
const char CLIENT_KEY[] = "Oly5D62FaE94W7";
const char WINDOWS_VERSION[] = "r70393861";
const uint8_t AES_KEY[] = {0xEC, 0xD4, 0x4F, 0x7B, 0xC6, 0xDD, 0x7D, 0xDE,
                           0x2B, 0x7B, 0x51, 0xAB, 0x4A, 0x6F, 0x5A, 0x22};
const uint8_t AES_IV[] = {'a', '@', '4', 'd', 'e', '%', '#', '1',
                          'a', 's', 'd', 'f', 's', 'd', '2', '4'};

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

size_t base64_encoded_length(size_t input_length) {
  // Each 3 bytes of input produce 4 bytes of output
  return ((input_length + 2) / 3) * 4;
}

int base64_encode(uint8_t *data, size_t input_length, size_t buffer_size) {
  if (data == NULL || buffer_size < base64_encoded_length(input_length)) {
    return -1; // Error: Buffer too small or invalid input
  }

  size_t output_length = base64_encoded_length(input_length);
  uint8_t output[output_length];

  size_t i, j;
  for (i = 0, j = 0; i < input_length; i += 3, j += 4) {
    uint32_t octet_a = i < input_length ? data[i] : 0;
    uint32_t octet_b = i < input_length ? data[i + 1] : 0;
    uint32_t octet_c = i < input_length ? data[i + 2] : 0;
    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    output[j] = base64_table[(triple >> 18) & 0x3F];
    output[j + 1] = base64_table[(triple >> 12) & 0x3F];
    output[j + 2] =
        (i + 1 < input_length) ? base64_table[(triple >> 6) & 0x3F] : '=';
    output[j + 3] = (i + 2 < input_length) ? base64_table[triple & 0x3F] : '=';
  }

  // Copy encoded data back to the original buffer
  memcpy(data, output, output_length);

  return output_length; // Return the length of the encoded data
}

void Xor(uint8_t *buffer, size_t buffer_len, const char *key, size_t key_len) {
  unsigned int i, j;
  for (i = 0; i < buffer_len; i++)
    buffer[i] ^= key[i % key_len];
  for (i = buffer_len - 1, j = 0; j < buffer_len; i--, j++)
    buffer[i] ^= key[j % key_len];
}

void md5_buffer(const uint8_t *buffer, size_t buffer_len, uint8_t *result) {
  MD5Context ctx;
  md5Init(&ctx);
  md5Update(&ctx, (const uint8_t *)buffer, buffer_len);
  md5Finalize(&ctx);
  memcpy(result, ctx.digest, 16);
}

void encrypted_client_version(uint8_t buffer[VERSION_BUFFER_SIZE]) {
  // Generate a random_key
  uint32_t random_n = (uint32_t)time(NULL);
  char random_key[8 + 1];
  sprintf(random_key, "%08x", random_n);
  // xor first 16-bytes data with key generated
  memcpy(buffer, CLIENT_VERSION, strlen(CLIENT_VERSION));
  Xor(buffer, 16, random_key, strlen(random_key));
  // then append the random_n, which is 4-bytes
  *(uint32_t *)(buffer + 16) = htonl(random_n);
  // xor 20 bytes in total
  Xor(buffer, VERSION_BUFFER_SIZE, CLIENT_KEY, strlen(CLIENT_KEY));
}

void encrypted_windows_version(uint8_t buffer[VERSION_BUFFER_SIZE]) {
  memcpy(buffer, WINDOWS_VERSION, strlen(WINDOWS_VERSION));
  Xor(buffer, VERSION_BUFFER_SIZE, CLIENT_KEY, strlen(CLIENT_KEY));
}

void based_encrypted_client_version(
    uint8_t buffer[base64_encoded_length(VERSION_BUFFER_SIZE)]) {
  encrypted_client_version(buffer);
  // base64 encode 20-bytes
  // -> 28 bytes encoded data
  base64_encode(buffer, VERSION_BUFFER_SIZE,
                base64_encoded_length(VERSION_BUFFER_SIZE));
}
