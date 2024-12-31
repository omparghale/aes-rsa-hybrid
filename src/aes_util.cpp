/*
 * This file uses OpenSSL's AES implementation for message encryption .
 *
 * Rationale:
 * - AES: OpenSSL's AES ensures efficient and secure symmetric encryption. The AES key derived here
 *   is subsequently encrypted using the project's "from-scratch RSA implementation". This highlights
 *   the hybrid encryption workflow while allowing the focus to remain on RSA's foundational principles.
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
typedef unsigned char byte;

// Handles OpenSSL errors and terminates the program
void handleErrors(void)
{
  ERR_print_errors_fp(stderr); // print openssl error stack to stderr
  abort();
}

// Generates a 128 bit key or initialization vector (IV)
std::vector<byte> generate16bytes(size_t len = 16)
{
  std::vector<byte> buffer(len);
  if (RAND_bytes(buffer.data(), len) != 1)
    throw std::runtime_error("Failed to generate key");
  return buffer;
}

// Encrypts plaintext using AES-128-CBC
int encrypt(const byte *plaintext, int plaintext_len,
            const std::vector<byte> &key, const std::vector<byte> &iv,
            std::vector<byte> &ciphertext)
{
  EVP_CIPHER_CTX *ctx; // Encryption context
  int len;             // Length of encrypted chunk
  int ciphertext_len;  // Total length of ciphertext

  // Create and initialize encryption  context
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  // Initialize encryption operation with AES-128-CBC
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
    handleErrors();

  // Preallocate ciphertext vector for encrypted data
  ciphertext.resize(plaintext_len + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

  // Encrypt the plaintext in chunks
  if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  // Finalise the encryption and handle padding
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    handleErrors();
  ciphertext_len += len;

  ciphertext.resize(ciphertext_len); // truncate excess space

  // Free the encryption context
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

// Decrypts ciphertext using AES-128-CBC
int decrypt(const std::vector<byte> &ciphertext, int ciphertext_len,
            const std::vector<byte> &key, const std::vector<byte> &iv,
            std::vector<byte> &decryptedtext)
{
  EVP_CIPHER_CTX *ctx;   // Decryption context
  int len;               // Length of decrypted chunk
  int decryptedtext_len; // Total length of decrypted text

  // Create and initialize decryption context
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  // Initialise the decryption operation
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data()))
    handleErrors();

  decryptedtext.resize(ciphertext_len); // Preallocate space for decryptedtext

  // Decrypt the ciphertext in chunks
  if (1 != EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, ciphertext.data(), ciphertext_len))
    handleErrors();
  decryptedtext_len = len;

  // Finalize decryption and handle padding
  if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext.data() + len, &len))
    handleErrors();
  decryptedtext_len += len;

  decryptedtext.resize(decryptedtext_len); // truncate excess space

  // Free the decryption context
  EVP_CIPHER_CTX_free(ctx);

  return decryptedtext_len;
}

// int main()
// {
//   // Generate a random 128-bit AES key and initialization vector (IV)
//   std::vector<byte> key = generate16bytes();
//   std::vector<byte> iv = generate16bytes();

//   // Plaintext message to encrypt
//   std::string msg = "And sometimes I am sorry when the grass\n"
//                     "Is growing over the stones in quiet hollows\n"
//                     "And the cocksfoot leans across the rutted cart-pass\n"
//                     "That I am not the voice of country fellows\n"
//                     "Who now are standing by some headland talking\n"
//                     "Of turnips and potatoes or young corn\n"
//                     "Of turf banks stripped for victory.\n"
//                     "Here Peace is still hawking\n"
//                     "His coloured combs and scarves and beads of horn.\n\n"
//                     "Upon a headland by a whinny hedge\n"
//                     "A hare sits looking down a leaf-lapped furrow\n"
//                     "There's an old plough upside-down on a weedy ridge\n"
//                     "And someone is shouldering home a saddle-harrow.\n"
//                     "Out of that childhood country what fools climb\n"
//                     "To fight with tyrants Love and Life and Time?";

//   const byte *plaintext = reinterpret_cast<const byte *>(msg.data()); // Cast to byte*
//   int plaintext_len = msg.size();

//   // Buffers for ciphertext and decrypted text
//   std::vector<byte> ciphertext;
//   std::vector<byte> decryptedtext;

//   int decryptedtext_len, ciphertext_len; // Variables to store lengths

//   // Encrypt the plaintext
//   ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);

//   // Cast ciphertext binaries to a string
//   std::string ciphertext_str(ciphertext.begin(), ciphertext.end());
//   std::cout << "Ciphertext: \n"
//             << ciphertext_str << "\n"
//             << std::endl;

//   // Decrypt the ciphertext
//   decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

//   // Cast decrypted plaintext binaries to a string
//   std::string decryptedtext_str(decryptedtext.begin(), decryptedtext.end());
//   std::cout << "Decrypted text: \n"
//             << decryptedtext_str << std::endl;

//   return 0;
// }