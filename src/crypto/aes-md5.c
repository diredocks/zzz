#include "../utils/log.h"
#include "aes.h"
#include "crypto.h"
#include "dict.h"
#ifdef _WIN32
#include <winsock2.h> // For ntohs and htons on Windows
#define htobe32(x) htonl(x)
#else
#include <arpa/inet.h> // For ntohs and htons on Linux
#endif
#include <stdio.h>
#include <string.h>

typedef struct {
  uint8_t offset;
  uint8_t length;
} DictQuery;

void append_to_buffer_direct(uint8_t *dest, int offset, const uint8_t *src,
                             size_t len) {
  memcpy(dest + offset, src, len);
}

void lookup_dict(uint8_t *key, uint8_t *value, DictQuery query) {
  char err[26];
  // get key
  uint32_t key_ = *(uint32_t *)key;
  key_ = htobe32(key_);
  // gey value
  const void *base_addr;
  switch (key_) {
  case 0x0BE169DA:
    base_addr = x0BE169DA;
    break;
  case 0x077AED1F:
    base_addr = x077AED1F;
    break;
  case 0x1A5776C9:
    base_addr = x1A5776C9;
    break;
  case 0x22E05E21:
    base_addr = x22E05E21;
    break;
  case 0x22D5BBE5:
    base_addr = x22D5BBE5;
    break;
  case 0x2C58D42D:
    base_addr = x2C58D42D;
    break;
  case 0x36F158CE:
    base_addr = x36F158CE;
    break;
  case 0x3367942B:
    base_addr = x3367942B;
    break;
  case 0x31A46D27:
    base_addr = x31A46D27;
    break;
  case 0x354E4205:
    base_addr = x354E4205;
    break;
  case 0x3F131A4E:
    base_addr = x3F131A4E;
    break;
  case 0x65C64E05:
    base_addr = x65C64E05;
    break;
  case 0x63355D54:
    base_addr = x63355D54;
    break;
  case 0x5BC95547:
    base_addr = x5BC95547;
    break;
  case 0x6555D892:
    base_addr = x6555D892;
    break;
  case 0x55AB5F34:
    base_addr = x55AB5F34;
    break;
  case 0x44F73BB5:
    base_addr = x44F73BB5;
    break;
  case 0x414E793A:
    base_addr = x414E793A;
    break;
  case 0x4C37ADF3:
    base_addr = x4C37ADF3;
    break;
  case 0x58DD8873:
    base_addr = x58DD8873;
    break;
  case 0x6FB7795F:
    base_addr = x6FB7795F;
    break;
  case 0x7EABA88E:
    base_addr = x7EABA88E;
    break;
  case 0x76F63D02:
    base_addr = x76F63D02;
    break;
  case 0x72B2F727:
    base_addr = x72B2F727;
    break;
  case 0x7243D3A3:
    base_addr = x7243D3A3;
    break;
  case 0x72D78AB9:
    base_addr = x72D78AB9;
    break;
  case 0x7EF5ADA7:
    base_addr = x7EF5ADA7;
    break;
  case 0xAC40ED9D:
    base_addr = xAC40ED9D;
    break;
  case 0xAC2DCCD3:
    base_addr = xAC2DCCD3;
    break;
  case 0x8F52F955:
    base_addr = x8F52F955;
    break;
  case 0x7F9773C0:
    base_addr = x7F9773C0;
    break;
  case 0xA97617A6:
    base_addr = xA97617A6;
    break;
  case 0xF435CA94:
    base_addr = xF435CA94;
    break;
  case 0xAC12139E:
    base_addr = xAC12139E;
    break;
  case 0xB7A23044:
    base_addr = xB7A23044;
    break;
  case 0xF94BD0C3:
    base_addr = xF94BD0C3;
    break;
  case 0xDBDB6398:
    base_addr = xDBDB6398;
    break;
  case 0xC6AD7541:
    base_addr = xC6AD7541;
    break;
  case 0xC0F90B5C:
    base_addr = xC0F90B5C;
    break;
  case 0xE813C036:
    base_addr = xE813C036;
    break;
  default:
    sprintf(err, "Key %08x not found", key_);
    log_warn(err, NULL);
  }
  memcpy(value, base_addr + query.offset, query.length);
}

void aes_128_decrypt(const uint8_t *in, uint8_t *out, size_t offset,
                     size_t length, const uint8_t *aes_key) {
  memcpy(out, in + offset, length);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, aes_key, AES_IV);
  AES_CBC_decrypt_buffer(&ctx, out, length);
}

uint8_t *challenge_response(const uint8_t *encrypted_data) {
  static uint8_t final_response[32];

  uint8_t decrypted_data[32];
  uint8_t decrypted_data2[32];

  // Decrypt the first block
  aes_128_decrypt(encrypted_data, decrypted_data, 0, 32, AES_KEY);

  // Lookup dictionary for the first query
  uint8_t lookup[256] = {0};
  DictQuery q = {decrypted_data[4], decrypted_data[5]};
  lookup_dict(decrypted_data, lookup, q);

  // Compute MD5 of the lookup result
  uint8_t md5_result[16];
  md5_buffer(lookup, q.length, md5_result);

  // Decrypt the second block
  aes_128_decrypt(decrypted_data, decrypted_data2, 16, 16, md5_result);

  // Combine decrypted blocks
  uint8_t decrypted[32];
  append_to_buffer_direct(decrypted, 0, decrypted_data, 16);
  append_to_buffer_direct(decrypted, 16, decrypted_data2, 16);

  // Lookup dictionary for the second query
  uint8_t lookup2[256] = {0};
  DictQuery q2 = {decrypted_data2[14], decrypted_data2[15]};
  lookup_dict(decrypted_data2 + 10, lookup2, q2);

  // Combine lookup results
  uint8_t combined[32] = {0};
  append_to_buffer_direct(combined, 0, lookup, q.length);
  append_to_buffer_direct(combined, decrypted_data[5], lookup2, q2.length);

  // Copy the appropriate size to the decrypted array
  if (q.length + q2.length > 32) {
    memcpy(decrypted, combined, 32);
  } else {
    memcpy(decrypted, combined, q.length + q2.length);
  }

  // Final MD5 hashing
  md5_buffer(decrypted, 32, final_response);
  md5_buffer(final_response, 16, final_response + 16);

  return final_response;
}
