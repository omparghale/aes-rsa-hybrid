#ifndef ENCODING_UTILS_H
#define ENCODING_UTILS_H

#include <string>
#include <cstdint>

// Encodes a 64 bit integer to a Base64 string
std::string encode_base64(const uint64_t &data);

// Decodes a Base64 string into a 64 bit integer
uint64_t decode_base64(const std::string &encoded_string);

// Creates a SHA256 hash from the input message
void create_digest(const unsigned char *message, size_t message_len,
                   unsigned char **digest, unsigned int *digest_len);

// Computes a SHA256 hash of a string and returns it in hexadecimal format
std::string sha256str(const std::string &msg);
#endif
