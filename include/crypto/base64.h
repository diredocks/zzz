#ifndef B64_H
#define B64_H

#include <stdint.h>
#include <stdlib.h>

#define BASE64_LENGTH(input_length) ((((input_length) + 2) / 3) * 4)

int base64_encode(uint8_t *data, size_t input_length, size_t buffer_size);

#endif // B64_H
