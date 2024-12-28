#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstring>
#include "encoding_utils.h"

// Converts a ASCII value to string
std::string ascii2text_str(uint64_t num)
{
  std::string temp = std::to_string(num);
  std::string res;

  for (int i = 0; i < temp.length();)
  {
    try
    {
      if (i + 2 <= temp.length() &&
          std::stoi(temp.substr(i, 2)) < 99 &&
          std::stoi(temp.substr(i, 2)) >= 32)
      {
        res += static_cast<char>(std::stoi(temp.substr(i, 2)));
        i += 2;
      }
      else if (i + 3 <= temp.length() &&
               std::stoi(temp.substr(i, 3)) >= 100 &&
               std::stoi(temp.substr(i, 3)) <= 255)
      {
        res += static_cast<char>(std::stoi(temp.substr(i, 3)));
        i += 3;
      }
      else
      {
        throw std::invalid_argument("Invalid ascii code");
      }
    }
    catch (const std::exception &e)
    {
      std::cerr << "Error: " << e.what() << std::endl;
      return "";
    }
  }
  return res;
}

// Converts a file from ASCII to text
std::string ascii2text_str_file_read(const std::string &path, char delimeter)
{
  std::string result, line;
  std::ifstream f(path);

  if (!f.is_open())
  {
    std::cerr << "Error opening the file!";
    return "";
  }

  while (std::getline(f, line))
  {
    result += line + "\n";
  }

  f.close();

  std::vector<int> tokens;
  std::stringstream ss(result);
  std::string token;

  while (std::getline(ss, token, delimeter)) // delimeter = " "
  {
    tokens.push_back(stoi(token));
  }

  std::string output;

  for (const auto &word : tokens)
  {
    output += (char)word;
  }

  return output;
}

std::string text2ascii_str(std::string s)
{
  std::string res;
  for (int i = 0; i < s.length(); i++)
  {
    res += std::to_string((int)s[i]);
  }
  return res;
}

uint64_t text2ascii_int(std::string s)
{
  s = text2ascii_str(s);
  return std::strtoull(s.c_str(), NULL, 0);
}

// Base64 encoding-decoding logic adapted from René Nyffenegger's implementation
// (http://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp/).

std::string encode_base64(const uint64_t &data)
{
  // Base64 character set
  std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // uint64_t to vector of bytes
  std::vector<uint8_t> binary(
      reinterpret_cast<const uint8_t *>(&data),
      reinterpret_cast<const uint8_t *>(&data) + sizeof(data));

  int padding_tok = 0; // Counter for padding tokens ('=')
  std::string encode;  // result

  // Process input bytes into chunks for 3 (24bits)
  for (size_t i = 0; i < binary.size(); i += 3)
  {
    uint32_t buffer = 0; // 24bit / 3 byte buffer
    size_t bytes_to_encode = std::min(size_t(3), binary.size() - i);

    // Pack bytes into 24bit buffer
    for (size_t j = 0; j < bytes_to_encode; ++j)
    {
      buffer |= (binary[i + j] << (16 - 8 * j));
    }
    // Encode 6bits at a time
    for (size_t j = 0; j < 4; ++j)
    {
      if (j <= bytes_to_encode + 1)
      {
        // Extract 6 bits from 24bit buffer and map against base64_chars
        encode += base64_chars[(buffer >> (18 - 6 * j)) & 0x3f];
      }
      else
      {
        // Add '=' for padding if fewer than 3 bytes in this chunk
        encode += '=';
        padding_tok++;
      }
    }
  }
  return encode;
}

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

    decoded.push_back((char0_pos << 2) | (char1_pos >> 4));   // Decode the first byte

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
