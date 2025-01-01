#ifndef AES_UTIL_H
#define AES_UTIL_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string>
typedef unsigned char byte;

void handleErrors(void);
std::vector<byte> generate16bytes(size_t len = 16);
int aes_encrypt(const byte *plaintext, int plaintext_len,
                const std::vector<byte> &key, const std::vector<byte> &iv,
                std::vector<byte> &ciphertext);

int aes_decrypt(const std::vector<byte> &ciphertext, int ciphertext_len,
                const std::vector<byte> &key, const std::vector<byte> &iv,
                std::vector<byte> &decryptedtext);

#endif