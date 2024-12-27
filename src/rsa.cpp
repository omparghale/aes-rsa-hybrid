#include <iostream>
#include <cstdint>
#include <random>
#include <bitset>
#include "rsa_math_utils.h"
#include "encoding_utils.h"
// #include<vector>
// #include <string>

struct RSAcrypt
{
  uint64_t k_pub;
  uint64_t k_priv;
  uint64_t mod;
  uint64_t phi_n;
  void public_key();
  void private_key(uint64_t k_pub, uint64_t phi_n);
  bool keypair_val(uint64_t k_pub, uint64_t k_priv, uint64_t phi_n);
  uint64_t encrypt(uint64_t plain_text, uint64_t k_pub, uint64_t mod);
  uint64_t decrypt(uint64_t cipher_text, uint64_t k_priv, uint64_t mod);
};

// Public Key generation
void RSAcrypt::public_key()
{
  uint64_t p = prime_num_gen();
  uint64_t q = prime_num_gen();
  phi_n = totient(p, q);
  mod = p * q;
  k_pub = 65537;
  if (coprimality_check(k_pub, phi_n))
  {
    return;
  }
  do
  {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(3, phi_n - 1);
    k_pub = dist(gen);
  } while (!coprimality_check(k_pub, phi_n));
}

// Private Key generation
void RSAcrypt::private_key(uint64_t k_pub, uint64_t phi_n)
{
  k_priv = mod_inv(k_pub, phi_n);
}

// Key pair validation => k_pub.k_priv === 1 mod(ϕ(n))
bool RSAcrypt::keypair_val(uint64_t k_pub, uint64_t k_priv, uint64_t phi_n)
{
  __uint128_t e = k_pub;
  __uint128_t d = k_priv;
  __uint128_t phi = phi_n;
  return (e * d % phi) == 1;
}

//  Encryption
uint64_t RSAcrypt::encrypt(uint64_t plain_text, uint64_t k_pub, uint64_t mod)
{
  if (plain_text > mod)
  {
    std::cout << "NOPE!" << std::endl;
  }
  return mod_exp(plain_text, k_pub, mod); // y = x^e mod(n)
}

// Decryption
uint64_t RSAcrypt::decrypt(uint64_t cipher_text, uint64_t k_priv, uint64_t mod)
{
  return mod_exp(cipher_text, k_priv, mod); // x = y^d mod(n)
}

// RSA pipeline for messages ∈ 2^59 to 2^60-1
void rsa_pipeline(uint64_t msg)
{
  RSAcrypt ex1;
  ex1.public_key();
  ex1.private_key(ex1.k_pub, ex1.phi_n);
  if (ex1.keypair_val(ex1.k_pub, ex1.k_priv, ex1.phi_n))
  {
    if (ex1.mod > msg)
    {
      std::cout << "Original message: " << msg << std::endl;
      uint64_t cipher_txt = ex1.encrypt(msg, ex1.k_pub, ex1.mod);
      std::cout << "Cipher text: " << cipher_txt << std::endl;
      uint64_t plain_txt = ex1.decrypt(cipher_txt, ex1.k_priv, ex1.mod);
      std::cout << "Decrypted message: " << plain_txt << std::endl;
    }
    else
    {
      std::cout << "Incompatible message lengths!";
    }
  }
  else
  {
    std::cout << "Incorrect key pair!";
  }
}

int main()
{
  std::cout << int2base64(0);
  return 0;
}