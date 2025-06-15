#include "crypto/base64.h"
#include <string.h>

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

int base64_encode(uint8_t *data, size_t input_length, size_t buffer_size) {
  if (data == NULL || buffer_size < BASE64_LENGTH(input_length)) {
    return -1; // Error: Buffer too small or invalid input
  }

  size_t output_length = BASE64_LENGTH(input_length);
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
