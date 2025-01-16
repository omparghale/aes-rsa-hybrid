#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
typedef unsigned char byte;

// Handles openssl errors 
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

// Encryption
int aes_encrypt(const byte *plaintext, int plaintext_len,
                const std::vector<byte> &key,
                const std::vector<byte> &iv,
                std::vector<byte> &ciphertext,
                const std::string &filename)
{
  EVP_CIPHER_CTX *ctx;                              // Encryption context
  int len;                                          
  int ciphertext_len;                               
  
  // Initialize encryption context
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
    handleErrors();

  ciphertext.resize(plaintext_len + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

  if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  // Finalise encryption (handles padding)
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    handleErrors();
  ciphertext_len += len;

  ciphertext.resize(ciphertext_len);

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

// Decryption
int aes_decrypt(const std::vector<byte> &ciphertext, int ciphertext_len,
                const std::vector<byte> &key, const std::vector<byte> &iv,
                std::vector<byte> &decryptedtext)
{
  EVP_CIPHER_CTX *ctx;   // Decryption context
  int len;               
  int decryptedtext_len; 

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
    handleErrors();

  decryptedtext.resize(ciphertext_len);

  // Decrypt the ciphertext in chunks
  if (1 != EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, ciphertext.data(), ciphertext_len))
    handleErrors();
  decryptedtext_len = len;

  // Finalize decryption (handles padding)
  if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext.data() + len, &len))
    handleErrors();
  decryptedtext_len += len;

  decryptedtext.resize(decryptedtext_len);

  EVP_CIPHER_CTX_free(ctx);

  return decryptedtext_len;
}
