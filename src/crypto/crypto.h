#ifndef D3XCRYPTO
#define D3XCRYPTO
#include <stddef.h>
#include <stdint.h>

#define VERSION_BUFFER_SIZE 20

extern const char CLIENT_VERSION[];
extern const char CLIENT_KEY[];
extern const char WINDOWS_VERSION[];
extern const uint8_t AES_KEY[];
extern const uint8_t AES_IV[];

void Xor(uint8_t buffer[], size_t buffer_len, const char key[], size_t key_len);

void encrypted_client_version(uint8_t buffer[VERSION_BUFFER_SIZE]);
void encrypted_windows_version(uint8_t buffer[VERSION_BUFFER_SIZE]);
int base64_encode(uint8_t *data, size_t input_length, size_t buffer_size);
size_t base64_encoded_length(size_t input_length);
// 28 bytes ascii base64 encoded client version
void based_encrypted_client_version(
    uint8_t buffer[base64_encoded_length(VERSION_BUFFER_SIZE)]);
void md5_buffer(const uint8_t *buffer, size_t buffer_len, uint8_t *result);
uint8_t *challenge_response(const uint8_t *encrypted_data);
#endif
