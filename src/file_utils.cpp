#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <iterator>
#include <sys/stat.h>
#include "encoding_utils.h"
#include "file_utils.h"

// Check if a file exists using sys/stat.h functions
bool fileExists(const std::string &filename)
{
  struct stat buffer;
  return (stat(filename.c_str(), &buffer) != -1);
}

// Read contents of a text file into a string
std::string getFileContent(const std::string &filename)
{
  std::string res, line;
  std::ifstream file(filename);
  if (!file.is_open())
    std::cerr << "Error opening text file";

  while (std::getline(file, line))
  {
    res += line + "\n";
  }
  file.close();
  return res;
}

// Writes an RSA key to a file
//
// Parameters:
// - filename: Path to the file where the key will be written.
// - mod: RSA modulus.
// - key: RSA public or private key.
// - type: Key type ("Public" or "Private").
void writeKey(const std::string &filename, uint64_t mod, uint64_t key, const std::string &type)
{
  // convert key type to uppercase for formatting
  std::string header = type;
  std::transform(header.begin(), header.end(), header.begin(), ::toupper);

  std::ofstream writeFile;
  writeFile.open(filename);
  if (!writeFile.is_open())
    throw std::runtime_error("Could not open file for writing");

  // Write the key in a readable format with Base64 encoding.
  writeFile << "-----BEGIN " << header << " KEY v1-----" << std::endl;
  writeFile << "Modulus:" << std::endl;
  writeFile << encode_base64(mod) << std::endl;
  writeFile << type << " exponent:" << std::endl;
  writeFile << encode_base64(key) << std::endl;
  writeFile << "------END " << header << " KEY v1------";

  writeFile.close();
}

// Reads an RSA key from a file in the format written by writeKey()
//
// Parameters:
// - filename: Path to the key file.
// - mod: Reference to store the RSA modulus.
// - key: Reference to store the RSA public or private key.
void readKey(const std::string &filename, uint64_t &mod, uint64_t &key)
{
  if (!fileExists(filename))
    throw std::runtime_error("Key file doesn't exist!");

  std::ifstream readFile;
  readFile.open(filename);
  if (!readFile.is_open())
    throw std::runtime_error("Could not open file for reading");

  // Parse the file line by line to extract the modulus and key.
  std::string line, modulus, exponent;
  while (std::getline(readFile, line))
  {
    if (line == "Modulus:")
    {
      std::getline(readFile, modulus);
    }
    else if (line == "Public exponent:" || line == "Private exponent:")
    {
      std::getline(readFile, exponent);
    }
  }
  mod = decode_base64(modulus);  // Decode the Base64 encoded modulus.
  key = decode_base64(exponent); // Decode the Base64 encoded key.

  readFile.close();
}

// Writes RSA ciphertext to a binary file
//
// Parameters:
// - filename: Path to the output file.
// - ciphertext: Vector of chiphertext chunks.
void writeRsaCiphertext(const std::string &filename,
                        const std::vector<uint64_t> &ciphertext)
{
  std::ofstream file(filename, std::ios::out | std::ios::binary);
  if (!file)
    throw std::runtime_error("Failed to open file for writing");

  // Write the ciphertext to the file in binary format.
  file.write(reinterpret_cast<const char *>(ciphertext.data()), sizeof(uint64_t) * ciphertext.size());
  if (!file)
    throw std::runtime_error("Failed to write RSA ciphertext into file");

  file.close();
}

// Writes AES ciphertext and its initialization vector (IV) to a binary file
//
// Parameters:
// - filename: Path to the output file.
// - iv: AES initialization vector.
// - ciphertext: AES-encrypted data.
void writeAesCipherText(const std::string &filename, const std::vector<byte> &iv, const std::vector<byte> &ciphertext)
{
  std::ofstream file(filename, std::ios::out | std::ios::binary);
  if (!file)
    throw std::runtime_error("Failed to open file for writing");

  // Write the IV and ciphertext sequentially.
  file.write(reinterpret_cast<const char *>(iv.data()), iv.size());
  if (!file)
    throw std::runtime_error("Failed to write the initialization vector into file");

  file.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
  if (!file)
    throw std::runtime_error("Failed to write the ciphertext to the file");

  file.close();
}

// Reads an AES ciphertext and its IV from a binary file.
//
// Parameters:
// - filename: Path to the input file.
// - iv: Vector to store the extracted IV. (16 bytes)
// - ciphertext: Vector to store the extracted ciphertext.
void readCiphertextIV(const std::string &filename, std::vector<byte> &iv, std::vector<byte> &ciphertext)
{
  std::ifstream file(filename, std::ios::binary);
  if (!file)
    throw std::runtime_error("Failed to open file for reading");

  file.unsetf(std::ios::skipws); // skip whitespaces during reading

  // get filesize
  std::streampos filesize;

  file.seekg(0, std::ios::end);
  filesize = file.tellg();
  file.seekg(0, std::ios::beg);

  // allocate memory and read file contents into a single vector
  std::vector<byte> data;
  data.reserve(filesize);
  data.insert(data.begin(),
              std::istream_iterator<byte>(file),
              std::istream_iterator<byte>());

  file.close();

  // split the data into IV and ciphertext
  iv.assign(data.begin(), data.begin() + 16);
  ciphertext.assign(data.begin() + 16, data.end());
}

// Writes a decrypted plaintext message to a file.
void writeDecrytedMsg(const std::string &filename,
                      const std::string &decrypted_text,
                      const std::string file_to_enc)
{
  std::ofstream file(filename, std::ios::out);
  if (!file)
    throw std::runtime_error("Failed to open the file to write");
  file << "Original encrypted file: " << file_to_enc << "\n";
  file << "----------------------------------------\n";
  file << decrypted_text;
  file.close();
}