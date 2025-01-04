#include <iostream>
#include <cstdint>
#include <random>
#include <vector>
#include <string>
#include "rsa.h"
#include "rsa_util.h"
#include "encoding_utils.h"
#include "aes_util.h"
#include "file_utils.h"
typedef unsigned char byte;

// Constructor
RSAcrypt::RSAcrypt()
{
  try
  { // Generate pkey pair
    public_key();
    private_key(k_pub, phi_n);

    // Save keys to files
    writeKey("keys/pubKey.pem", mod, k_pub, "Public");
    writeKey("keys/privKey.pem", mod, k_priv, "Private");

    // Validate the generated key pair
    if (!keypair_val(k_pub, k_priv, phi_n))
    {
      throw std::runtime_error("Key pair validation failed!");
    }
  }
  catch (const std::exception &e)
  {
    std::cerr << "Key generation failed: " << e.what() << std::endl;
    throw;
  }
}

// Public Key generation
void RSAcrypt::public_key()
{
  uint64_t p = prime_num_gen();
  uint64_t q = prime_num_gen();
  phi_n = totient(p, q);
  mod = p * q;

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dist(3, phi_n - 1);

  k_pub = dist(gen);
  if (coprimality_check(k_pub, phi_n))
  {
    return;
  }
  do
  {
    k_pub = dist(gen);
  } while (!coprimality_check(k_pub, phi_n));
}

// Private Key generation
void RSAcrypt::private_key(uint64_t k_pub, uint64_t phi_n)
{
  k_priv = mod_inv(k_pub, phi_n);
}

// Key pair validation,check if k_pub * k_priv ≡ 1 (mod phi_n)
bool RSAcrypt::keypair_val(uint64_t k_pub, uint64_t k_priv, uint64_t phi_n)
{
  __uint128_t e = k_pub;
  __uint128_t d = k_priv;
  __uint128_t phi = phi_n;
  return (e * d % phi) == 1;
}

// PKCS#1 Padding:
// Structure: 0x00 || 0x02 || 4 random bytes || 0x00 || 1-byte message
// - The modulus range is 2^62 <=mod <2^64
// - Padded message fits within the mod as the first 14 MSB are 0.
uint64_t pkcs1_pad(const byte chunk)
{
  uint64_t padded_msg = 0;

  // Generate 4 random bytes for padding
  std::random_device seed;
  std::mt19937 generator(seed());
  std::uniform_int_distribution<uint64_t> dist((1ULL << 31), (1ULL << 32) - 1);

  padded_msg |= chunk;                   // Add the message byte
  padded_msg |= (dist(generator) << 16); // Add 4 byte random padding
  padded_msg |= (0x02ULL << 48);         // Add the 0x02 seperator
  return padded_msg;
}

// Removes PKCS#1 padding and extracts original message byte
byte pkcs1_unpad(uint64_t padded_msg)
{
  return padded_msg & 0xFF;
}

// RSA Encryption: Encrypts each byte of the AES key using the RSA public key
//
// Parameters:
// - k_pub: RSA public key (e).
// - mod: RSA modulus (n).
// - aeskey: AES key to be encrypted(vector of bytes)
// - ciphertext: Encrypted RSA ciphertext (vector of uint64_t).
// - filename: File to save the encrypted RSA ciphertext.
void RSAcrypt::rsa_encrypt(uint64_t k_pub, uint64_t mod,
                           const std::vector<byte> &aeskey,
                           std::vector<uint64_t> &ciphertext,
                           const std::string &filename)
{
  if (mod == 0)
  {
    throw std::runtime_error("Modulus wasn't initialized, call RSAcrypt::public_key() first.");
  }

  // Byte-wise encryption of the AES key
  for (size_t i = 0; i < aeskey.size(); ++i)
  {
    uint64_t padded_msg = pkcs1_pad(aeskey[i]);           // Apply PKCS#1 padding
    uint64_t enc_chunk = mod_exp(padded_msg, k_pub, mod); // Encrypt using modular exponentionation
    ciphertext.push_back(enc_chunk);
  }
  writeRsaCiphertext(filename, ciphertext);
}

// RSA Decryption: Decrypts the RSA ciphertext to retrieve the original AES key
//
// Parameters:
// - k_priv: RSA private key (d).
// - mod: RSA modulus (n).
// - ciphertext: Encrypted RSA ciphertext(vector of uint64_t).
// - decrypted: Decrypted AES key(vector of bytes).
void RSAcrypt::rsa_decrypt(uint64_t k_priv, uint64_t mod,
                           std::vector<uint64_t> &ciphertext,
                           std::vector<byte> &decrypted)
{
  // Decrypt each chunk of the ciphertext
  for (size_t i = 0; i < ciphertext.size(); ++i)
  {
    uint64_t dec_chunk = mod_exp(ciphertext[i], k_priv, mod); // Decrypt using modular exponentiation.
    decrypted.push_back(pkcs1_unpad(dec_chunk));
  }
}