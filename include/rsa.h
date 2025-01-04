/*
 * In real-world systems:
 * - RSA keys are stored in ASN.1/DER format for compatibility.
 * - Public keys are shared in PEM format (Base64-encoded ASN.1).
 * - Private keys are securely stored in systems like HSMs or encrypted files.
 *
 * This project simplifies key handling for learning purposes and does not use these standards.
 */

#ifndef RSA_H
#define RSA_H

#include <cstdint>
#include <vector>
#include <random>
#include <stdexcept>
#include <string>
typedef unsigned char byte;

// RSAcrypt handles key pair generation, encryption and decryption
struct RSAcrypt
{
    uint64_t k_pub = 0;  // Public key (e)
    uint64_t k_priv = 0; // Private key (d).
    uint64_t mod = 0;    // Modulus (n).
    uint64_t phi_n = 0;  // Totient (ϕ(n))

    RSAcrypt(); // Generates keys

    void public_key();                                                 // Generates the public key
    void private_key(uint64_t k_pub, uint64_t phi_n);                  // Computes private key
    bool keypair_val(uint64_t k_pub, uint64_t k_priv, uint64_t phi_n); // Validates key pair
    void rsa_encrypt(uint64_t k_pub, uint64_t mod,
                     const std::vector<byte> &aeskey,
                     std::vector<uint64_t> &ciphertext,
                     const std::string &filename); // Encrypts AES key with RSA
    void rsa_decrypt(uint64_t k_priv, uint64_t mod,
                     std::vector<uint64_t> &ciphertext,
                     std::vector<byte> &decrypted); // Decrypts AES key with RSA
};

// Adds PKCS#1 padding to a message chunk
uint64_t pkcs1_pad(const byte chunk);

// Removes PKCS#1 padding to a message chunk
byte pkcs1_unpad(uint64_t padded_msg);

#endif // RSA_H
