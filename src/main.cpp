/*
 * main.cpp
 *
 * Description:
 * This program demonstrates a hybrid encryption workflow combining:
 * - AES (Advanced Encryption Standard) for efficient symmetric encryption of a
 * plaintext message.
 * - RSA (Rivest-Shamir-Adleman) for secure asymmetric encryption of the AES
 * key.
 *
 * Workflow:
 * 1. The user provides a plaintext file to encrypt.
 * 2. AES encrypts the plaintext, generating a random AES key and IV.
 * 3. RSA encrypts the AES key, ensuring secure transmission.
 * 4. Both ciphertexts (message and encrypted AES key) are saved to files.
 * 5. During decryption, the RSA-encrypted AES key is decrypted first.
 * 6. The decrypted AES key is used to decrypt the original message.
 *
 * Key Features:
 * - AES and RSA implementation written from scratch (without third-party
 * cryptography libraries).
 * - CBC mode to make AES probabilistic by chaining blocks.
 * - PKCS#7 padding applied to AES-encrypted data.
 * - PKCS#1 padding applied to RSA-encrypted data.
 * - Extensive logging for clarity and debugging.
 *
 * Note:
 * This project is for educational purposes and demonstrates RSA implementation
 * principles. It is not optimized for production use due to limitations in key
 * size and security guarantees.
 */

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "aes_util.h"
#include "encoding_utils.h"
#include "file_utils.h"
#include "rsa.h"
#include "rsa_util.h"

int main(int argc, char* argv[]) {
  rmFile();  // Clear previous log file
  Logger("Program started");

  // Get the path to the text file to encrypt
  std::string file_to_encrypt = argv[1];
  if (!std::filesystem::exists(file_to_encrypt)) {
    Logger("Error: File " + file_to_encrypt + " does not exist.");
    throw std::runtime_error("File not found");
  }

  // Read the file content into a string
  fileContent content = getFileContent(file_to_encrypt);
  Logger("Plaintext file (" + file_to_encrypt + ") read successfully\n");

  Logger("===== Encryption Phase =====");

  // AES encryption setup
  Logger("Starting AES encryption of plaintext...");
  std::vector<byte> aeskey = generate16bytes();  // Generate a random AES key
  std::vector<byte> iv = generate16bytes();      // Generate a random IV
  std::vector<byte> aes_ciphertext, aes_decryptedtext;
  int ciphertext_len, decryptedtext_len;
  std::string aes_ciphertext_path = "ciphertext/msg_enc.aes";

  // Encrypt message with AES and savit it to a file
  ciphertext_len = enc_aes_128_cbc(content.padded_buf, content.filesize, aeskey,
                                   iv, aes_ciphertext);
  writeAesCipherText(aes_ciphertext_path, iv, aes_ciphertext);
  std::memset(iv.data(), 0, iv.size());
  std::memset(aes_ciphertext.data(), 0, aes_ciphertext.size());
  Logger("AES ciphertext written to: " + aes_ciphertext_path);

  // RSA encryption for the AES key
  RSAcrypt rsa;  // Initialize RSA cryptography object from rsa.cpp
  std::vector<uint64_t> rsa_ciphertext;  // Encrypted AES key
  std::vector<byte> rsa_decryptedtext;   // Decrypted AES key
  std::string pubKey_path = "keys/pubKey.pem";
  std::string privKey_path = "keys/privKey.pem";
  std::string rsa_ciphertext_path = "ciphertext/key_enc.bin";

  // Read key pair
  uint64_t modulus, k_pub, k_priv;
  readKey(pubKey_path, modulus, k_pub);
  readKey(privKey_path, modulus, k_priv);

  Logger(
      "RSA keys generated successfully.\n"
      "                    Public key: " +
      sha256str(std::to_string(k_pub)) +
      ",\n                    Private key: " +
      sha256str(std::to_string(k_priv)) +
      "\n                    Note: RSA keys are "
      "hashed (SHA-256) before logging for security purposes.");
  Logger("Base64 encoded public key exported to: " + pubKey_path);
  Logger("Base64 encoded private key exported to: " + privKey_path);

  // Encrypt the AES key using RSA and save it to a file
  Logger("RSA encrypting the AES key using public key...");
  rsa.rsa_encrypt(k_pub, modulus, aeskey, rsa_ciphertext, rsa_ciphertext_path);
  Logger("RSA ciphertext (encrypted AES key) saved to: " + rsa_ciphertext_path +
         "\n");

  Logger("===== Decryption Phase =====");

  // Decrypt the RSA-encrypted AES key
  Logger("RSA decrypting the AES key using private key...");
  rsa.rsa_decrypt(k_priv, modulus, rsa_ciphertext, rsa_decryptedtext);
  Logger("AES key successfully recovered.");

  // Read the IV and ciphertext from encrypted file
  readCiphertextIV(aes_ciphertext_path, iv, aes_ciphertext);
  Logger(
      "AES ciphertext and Initialization Vector (IV) successfully deserialized "
      "from: " +
      aes_ciphertext_path);

  // Decrypt the AES-encrypted message using the decrypted AES key
  Logger("Starting AES decryption of the ciphertext...");
  decryptedtext_len = dec_aes_128_cbc(rsa_decryptedtext, iv, aes_ciphertext,
                                      aes_decryptedtext, aes_ciphertext.size());
  Logger("AES decryption completed.");

  // Write decrpyted data out to it's original form
  std::string decrypted_filepath =
      "./test/decrypted" + getFileExtension(file_to_encrypt);
  writeDecrytedMsg(aes_decryptedtext, decrypted_filepath);
  Logger("Decrypted message exported to: " + std::string(decrypted_filepath));

  // Verify decrypted message matches original plaintext
  if (areFileIdentical(content.og_buf, aes_decryptedtext)) {
    Logger("Decrypted file matches the original file.\n");
  }

  Logger("Program finished successfully.");
  return 0;
}
