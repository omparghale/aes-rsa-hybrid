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

// Converts a 64 bit ASCII value to its string representation
std::string ascii2text_str(uint64_t num);

// Reads ASCII values from a file and converts them into a string
std::string ascii2text_str_file_read(const std::string &path, char delimeter);

// Converts a string to its ASCII representation as a concatenated string
std::string text2ascii_str(std::string s);

// Converts a string to its ASCII representation as a 64-bit integer
uint64_t text2ascii_int(std::string s);

#endif
