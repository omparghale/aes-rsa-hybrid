/*
 * AES-128-CBC Test Vector Runner
 *
 * This file implements test vector validation for AES-128-CBC implementation.
 * It reads test vectors (key, IV, plaintext, expected ciphertext) and verifies:
 * 1. Encryption: Checks if encryption output matches expected ciphertext
 * 2. Decryption: Verifies if decryption of the ciphertext gives original plaintext
 * All inputs/outputs are in hex format.
 */

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "include/aes_util.h"

struct TestVector
{
  std::string key;
  std::string iv;
  std::string plaintext;
  std::string ciphertext;
  std::string name;
};

std::vector<unsigned char> hex_to_bytes(std::string hex)
{
  std::vector<unsigned char> bytes;
  for (int i = 0; i < hex.length(); i += 2)
  {
    std::string byte = hex.substr(i, 2);
    bytes.push_back(std::stoi(byte, nullptr, 16));
  }
  return bytes;
}

std::string bytes_to_hex(std::vector<unsigned char> bytes)
{
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (unsigned char byte : bytes)
  {
    ss << std::setw(2) << (int)byte;
  }
  return ss.str();
}

void run_test_vector(TestVector test, int test_num, std::ofstream &log_file)
{
  log_file << "\nTest Vector " << test_num << ": " << test.name << std::endl;
  log_file << "----------------------------------------" << std::endl;
  log_file << "Key       : " << test.key << std::endl;
  log_file << "IV        : " << test.iv << std::endl;
  log_file << "Plaintext : " << test.plaintext << std::endl;

  try
  {
    // Convert inputs from hex
    auto key = hex_to_bytes(test.key);
    auto iv = hex_to_bytes(test.iv);
    auto pt_bytes = hex_to_bytes(test.plaintext);
    std::string pt_str(pt_bytes.begin(), pt_bytes.end());

    // Encryption test
    std::vector<unsigned char> ciphertext;
    enc_aes_128_cbc(pt_str, key, iv, ciphertext);
    ciphertext.resize(16); // keep only first block

    std::string result = bytes_to_hex(ciphertext);
    log_file << "\nEncryption Test:" << std::endl;
    log_file << "Expected : " << test.ciphertext << std::endl;
    log_file << "Got      : " << result << std::endl;
    log_file << "Status   : " << (result == test.ciphertext ? "[PASS]" : "[FAIL]") << std::endl;

    // Decryption test
    std::vector<unsigned char> decrypted;
    dec_aes_128_cbc(key, iv, ciphertext, decrypted, ciphertext.size(), true);

    std::string dec_result = bytes_to_hex(decrypted);
    log_file << "\nDecryption Test:" << std::endl;
    log_file << "Expected : " << test.plaintext << std::endl;
    log_file << "Got      : " << dec_result << std::endl;
    log_file << "Status   : " << (dec_result == test.plaintext ? "[PASS]" : "[FAIL]") << std::endl;
  }
  catch (std::exception &e)
  {
    log_file << "Test failed with error: " << e.what() << std::endl;
  }
}

/*
int main()
{
  // Open log file
  std::ofstream log_file("/test/aes_test_result.txt");
  if (!log_file)
  {
    std::cerr << "Failed to open /test/aes_test_result.txt" << std::endl;
    return 1;
  }

  log_file << "AES-128-CBC Implementation Test Results" << std::endl;
  log_file << "======================================" << std::endl;

  std::vector<TestVector> test_vectors = {
      {
          "00000000000000000000000000000000", // key
          "00000000000000000000000000000000", // iv
          "f34481ec3cc627bacd5dc3fb08f273e6", // plaintext
          "0336763e966d92595a567cc9ce537f5e", // expected ciphertext
          "NIST SP800-38A CBC-AES128.Encrypt" // source
      },
      {"fffffffffffffffffffffffff0000000",
       "00000000000000000000000000000000",
       "00000000000000000000000000000000",
       "307c5b8fcd0533ab98bc51e27a6ce461",
       "NIST Sample Test Vector #2"},
      {"00000000000000000000000000000000",
       "00000000000000000000000000000000",
       "ffffffffffffffffffffffffff800000",
       "63919ed4ce10196438b6ad09d99cd795",
       "NIST Sample Test Vector #3"},
      {"00000000000000000000000000000000",
       "00000000000000000000000000000000",
       "fffffffffffe00000000000000000000",
       "c2f93a4ce5ab6d5d56f1b93cf19911c1",
       "NIST Sample Test Vector #4"},
      {"fffffffffffffffffc00000000000000",
       "00000000000000000000000000000000",
       "00000000000000000000000000000000",
       "ab69cfadf51f8e604d9cc37182f6635a",
       "NIST Sample Test Vector #5"}};

  for (int i = 0; i < test_vectors.size(); i++)
  {
    run_test_vector(test_vectors[i], i + 1, log_file);
  }

  log_file << "\nTest process completed." << std::endl;
  log_file.close();

  std::cout << "Test results have been written to /test/aes_test_result.txt" << std::endl;
  return 0;
}
*/
