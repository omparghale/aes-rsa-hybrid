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

void handleErrors(void); // Handle openssl errors.

// Generates a random byte array of specified length (default: 16 bytes)
std::vector<byte> generate16bytes(size_t len = 16);

// Encrypts plaintext using AES-128-CBC and writes ciphertext to a file
int aes_encrypt(const byte *plaintext, int plaintext_len,
                const std::vector<byte> &key,
                std::vector<byte> &ciphertext, const std::string &filename);

// Decrypts AES-128-CBC ciphertext using the provided key and IV
int aes_decrypt(const std::vector<byte> &ciphertext, int ciphertext_len,
                const std::vector<byte> &key, const std::vector<byte> &iv,
                std::vector<byte> &decryptedtext);

#endif