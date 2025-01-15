#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
typedef unsigned char byte;

// // Handles openssl errors by printing the error stack and terminates the program
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

// Generates a random 128 bit key or initialization vector (IV)
std::vector<byte> generate16bytes(size_t len)
{
  std::vector<byte> buffer(len);
  if (RAND_bytes(buffer.data(), len) != 1)
    throw std::runtime_error("Failed to generate key");
  return buffer;
}

// Encrypts plaintext using AES-128-CBC adn writes the result to a file
//
// Parameters:
// - plaintext: Pointer to the plaintext data.
// - plaintext_len: Length of the plaintext.
// - key: 128 bit AES key for encryption.
// - ciphertext: Vector to hold the encrypted data.
// - filename: File to store the ciphertext and IV.
//
// returns: Length of the ciphertext.

int aes_encrypt(const byte *plaintext, int plaintext_len,
                const std::vector<byte> &key,
                const std::vector<byte> &iv,
                std::vector<byte> &ciphertext,
                const std::string &filename)
{
  EVP_CIPHER_CTX *ctx;                              // Encryption context
  int len;                                          // Length of processed chunk
  int ciphertext_len;                               // Total length of ciphertext
  
  // Initialize encryption context
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  // Set up encryption operation with AES-128-CBC
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
    handleErrors();

  // Preallocate space for ciphertext
  ciphertext.resize(plaintext_len + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

  // Encrypt the plaintext in chunks
  if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  // Finalise encryption (handles padding)
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    handleErrors();
  ciphertext_len += len;

  // resize ciphertext vector to match actual data length
  ciphertext.resize(ciphertext_len);

  // Free the encryption context
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

// Decrypts ciphertext using AES-128-CBC
//
// Parameters:
// - ciphertext: The encrypted data to decrypt.
// - ciphertext_len: Length of the ciphertext.
// - key: 128 bit AES key for decryption.
// - iv: Initialization vector used during encryption.
// - decryptedtext: Vector to hold the decrypted data.
//
// returns: Length of the decrypted plaintext.
int aes_decrypt(const std::vector<byte> &ciphertext, int ciphertext_len,
                const std::vector<byte> &key, const std::vector<byte> &iv,
                std::vector<byte> &decryptedtext)
{
  EVP_CIPHER_CTX *ctx;   // Decryption context
  int len;               // Length of processed chunk
  int decryptedtext_len; // Total length of decrypted text

  // Initialize decryption context
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  // Set up the decryption operation
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
    handleErrors();

  decryptedtext.resize(ciphertext_len); // Preallocate space for decrypted text

  // Decrypt the ciphertext in chunks
  if (1 != EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, ciphertext.data(), ciphertext_len))
    handleErrors();
  decryptedtext_len = len;

  // Finalize decryption (handles padding)
  if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext.data() + len, &len))
    handleErrors();
  decryptedtext_len += len;

  // resize the decrypted plaintext vector to match actual data length
  decryptedtext.resize(decryptedtext_len);

  // Free the decryption context
  EVP_CIPHER_CTX_free(ctx);

  return decryptedtext_len;
}
