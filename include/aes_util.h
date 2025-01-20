#ifndef AES_UTIL_H
#define AES_UTIL_H
#include <cstdint>
#include <string>
#include <vector>
typedef unsigned char byte;

std::vector<byte> generate16bytes();
int enc_aes_128_cbc(std::vector<byte> &buffer, size_t og_filesize,
                    const std::vector<byte> &key, const std::vector<byte> &iv,
                    std::vector<byte> &ciphertext);
int dec_aes_128_cbc(const std::vector<byte> &key, const std::vector<byte> &iv,
                    const std::vector<byte> &ciphertext,
                    std::vector<byte> &decryptedtext, int ciphertext_len,
                    bool test_mode = false);

#endif  // AES_UTIL_H
