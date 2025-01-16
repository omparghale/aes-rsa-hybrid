#ifndef AES_UTIL_H
#define AES_UTIL_H
#include <vector>
#include <cstdint>
#include <string>
typedef unsigned char byte;

std::vector<byte> generate16bytes();
void pkcs7_pad(std::vector<byte> &input);
void pkcs7_unpad(std::vector<byte> &input, bool test_mode);
int enc_aes_128_cbc(const std::string &og_str,
                    const std::vector<byte> &key,
                    const std::vector<byte> &iv,
                    std::vector<byte> &ciphertext);
int dec_aes_128_cbc(const std::vector<byte> &key,
                    const std::vector<byte> &iv,
                    const std::vector<byte> &ciphertext,
                    std::vector<byte> &decryptedtext,
                    int ciphertext_len,
                    bool test_mode=false);

#endif // AES_UTIL_H