#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "encoding_utils.h"

// SHA256 for hashing public and private keys
// https://wiki.openssl.org/index.php/EVP_Message_Digests

// Handles openssl errors
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

// Creates a SHA-256 digest from a message
void create_digest(const unsigned char *message, size_t message_len,
                   unsigned char **digest, unsigned int *digest_len)
{
  EVP_MD_CTX *mdctx;

  if ((mdctx = EVP_MD_CTX_new()) == NULL)
    handleErrors();

  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    handleErrors();

  if (1 != EVP_DigestUpdate(mdctx, message, message_len))
    handleErrors();

  if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
    handleErrors();

  if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
    handleErrors();

  EVP_MD_CTX_free(mdctx);
}

// Returns the SHA256 hash of a string as a hexadecimal string
std::string sha256str(const std::string &msg)
{
  std::string hash;
  unsigned char *digest = nullptr; // pointer to hold binary hash
  unsigned int digest_len = 0;

  create_digest(reinterpret_cast<const unsigned char *>(msg.data()),
                msg.size(), &digest, &digest_len);

  // convert binary digest to hexadecimal string
  for (auto i = 0; i < digest_len; ++i)
  {
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    hash += oss.str();
  }

  OPENSSL_free(digest);
  return hash;
}

// Base64 encoding-decoding logic adapted from René Nyffenegger's implementation
// (http://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp/).

// Encodes a 64 bit integer into a Base64 string
std::string encode_base64(const uint64_t &data)
{
  // Base64 character set
  std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // Convert the 64 bit integer into a vector of 8 bytes
  std::vector<uint8_t> binary(
      reinterpret_cast<const uint8_t *>(&data),
      reinterpret_cast<const uint8_t *>(&data) + sizeof(data));

  std::string encode;

  // Process the bytes in groups of 3
  for (size_t i = 0; i < binary.size(); i += 3)
  {
    uint32_t buffer = 0;
    size_t bytes_to_encode = std::min(size_t(3), binary.size() - i);

    // Pack up to 3 bytes into a 24 bit buffer
    for (size_t j = 0; j < bytes_to_encode; ++j)
    {
      buffer |= (binary[i + j] << (16 - 8 * j));
    }
    // Convert each 6 bits of the 24 bit buffer into a Base64 character
    for (size_t j = 0; j < 4; ++j)
    {
      if (j <= bytes_to_encode)
      {
        encode += base64_chars[(buffer >> (18 - 6 * j)) & 0x3f];
      }
      else
      {
        // Add '=' for padding if fewer than 3 bytes in this chunk
        encode += '=';
      }
    }
  }
  return encode;
}

// Decodes a Base64 string into a 64 bit integer
uint64_t decode_base64(const std::string &encoded_string)
{
  std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<uint8_t> decoded; // Stores decoded bytes
  uint64_t decoded_int = 0;
  size_t pos = 0;
  size_t len = encoded_string.length();

  while (pos + 3 < len)
  {
    // Find positions of the current 4 characters in the Base64 table
    unsigned int char0_pos = base64_chars.find(encoded_string[pos]);
    unsigned int char1_pos = base64_chars.find(encoded_string[pos + 1]);
    unsigned int char2_pos = base64_chars.find(encoded_string[pos + 2]);
    unsigned int char3_pos = base64_chars.find(encoded_string[pos + 3]);

    // Stop if padding character '=' is encountered
    if (encoded_string[pos + 1] == '=' || encoded_string[pos + 2] == '=')
    {
      break;
    }

    decoded.push_back((char0_pos << 2) | (char1_pos >> 4)); // Decode the first byte

    if (encoded_string[pos + 2] != '=')
    {
      decoded.push_back(((char1_pos & 0b1111) << 4) | (char2_pos >> 2));
    }

    if (encoded_string[pos + 3] != '=')
    {
      decoded.push_back(((char2_pos & 0b11) << 6 | (char3_pos)));
    }
    pos += 4;
  }
  memcpy(&decoded_int, decoded.data(), std::min(sizeof(decoded_int), decoded.size()));
  return decoded_int;
}
