#include <iostream>
#include <cstdint>
#include <random>
#include <bitset>
#include <iomanip>
#include <algorithm>
#include "rsa_util.h"
#include "encoding_utils.h"
#include "aes_util.h"
#include <vector>
#include <string>
typedef unsigned char byte;

struct RSAcrypt
{
  uint64_t k_pub = 0;
  uint64_t k_priv = 0;
  uint64_t mod = 0;
  uint64_t phi_n = 0;
  void public_key();
  void private_key(uint64_t k_pub, uint64_t phi_n);
  bool keypair_val(uint64_t k_pub, uint64_t k_priv, uint64_t phi_n);
  uint64_t encrypt(uint64_t plain_text, uint64_t k_pub, uint64_t mod);
  uint64_t decrypt(uint64_t cipher_text, uint64_t k_priv, uint64_t mod);

  // Generate keys
  RSAcrypt()
  {
    try
    {
      public_key();
      private_key(k_pub, phi_n);
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
  if (mod == 0)
  {
    throw std::runtime_error("Modulus wasn't initialized, call RSAcrypt::public_key() first.");
  }
  if (plain_text > mod)
  {
    std::cerr << "Warning: Message length greater than modulus!\n";
  }
  return mod_exp(plain_text, k_pub, mod); // y = x^e mod(n)
}

// Decryption
uint64_t RSAcrypt::decrypt(uint64_t cipher_text, uint64_t k_priv, uint64_t mod)
{
  return mod_exp(cipher_text, k_priv, mod); // x = y^d mod(n)
}

/* Padding:
 Pad the each 8 bit chunk of the 128 bit aes key using the PKCS#1 padding scheme
 Structure of the padding scheme we are using here:
  - 0x00 || 0x02 || random number (4 bytes) || 0x00 || 1 byte message
  - In our project  2^62 <=mod <2^64
  - Thus padded message fits within the mod since first 14 bits from msb are 0
*/
uint64_t pkcs1_pad(const byte chunk)
{
  uint64_t padded_msg = 0; // final padded message initialized as all 0

  // Generate 4 random bytes for padding
  std::random_device seed;
  std::mt19937 generator(seed());
  std::uniform_int_distribution<uint64_t> dist((1ULL << 31), (1ULL << 32) - 1);

  padded_msg |= chunk;                   // add message chunk to the lsb
  padded_msg |= (dist(generator) << 16); // add 4 random bytes. Lsh 16 accounts for message chunk and 0x00 byte
  padded_msg |= (0x02ULL << 48);         // add 0x02 seperator after the 32 bit random number
  return padded_msg;
}

// Unpad after decryption
byte pkcs1_unpad(uint64_t padded_msg)
{
  return padded_msg & 0xFF; // Bit mask of 0xFF for 1 byte msg
}

// RSA pipeline
void rsa_pipeline(const std::vector<byte> &aeskey, std::vector<uint64_t> &ciphertext, std::vector<byte> &decrypted_aeskey)
{
  RSAcrypt rsa_proc;

  // Encryption
  for (size_t i = 0; i < aeskey.size(); ++i)
  {
    uint64_t padded_msg = pkcs1_pad(aeskey[i]);
    ciphertext.push_back(rsa_proc.encrypt(padded_msg, rsa_proc.k_pub, rsa_proc.mod));
  }

  // Decryption
  for (size_t i = 0; i < ciphertext.size(); ++i)
  {
    uint64_t dec_pad = rsa_proc.decrypt(ciphertext[i], rsa_proc.k_priv, rsa_proc.mod);
    decrypted_aeskey.push_back(pkcs1_unpad(dec_pad));
  }
}

int main()
{
  // std::vector<byte> aeskey = generate16bytes();
  std::vector<byte> same = {0x98, 0x6E, 0x4F, 0x72, 0xC6, 0x02, 0xD9, 0x70, 0xF4, 0xC8, 0x23, 0xEB, 0x1E, 0x0D, 0x8B, 0x7A};
  std::vector<uint64_t> ciphertext;
  std::vector<byte> decrypted_key;
  std::cout << "Original AES key: \n";
  for (auto k : same)
  {
    std::cout << (int)k << " ";
  }
  std::cout << "\n"
            << std::endl;

  // Run the process
  rsa_pipeline(same, ciphertext, decrypted_key);
  std::cout << "Cipher text: \n";
  for (auto c : ciphertext)
  {
    std::cout << c;
  }
  std::cout << "\n"
            << std::endl;

  std::cout << "Decrypted AES key: \n";
  for (auto d : decrypted_key)
  {
    std::cout << (int)d << " ";
  }

  return 0;
}
