/*
 * AES-128-CBC Implementation
 * WARNING: Educational purposes only. Not for production use.
 *
 * Features:
 * - PKCS7 padding
 * - CBC mode operation
 * - Supports Windows and Unix random number generation
 */

#include <openssl/rand.h>  // for key & iv generation

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "aes_util.h"
typedef unsigned char byte;

/*
 * AES Utility Data and Functions:
 * - sBox: AES substitution box for encryption (used in SubBytes step)
 * - inv_sBox: AES inverse substitution box for decryption (used in InvSubBytes
 * step)
 * - rcon: Round constants for key expansion (used in key schedule)
 * - gf_mul: Galois Field multiplication (used in MixColumns step)
 * - generate16bytes: Generates a random 16-byte key or IV
 * - g_func: Non-linear function for key expansion (used in key schedule)
 * - keySchedule: Derives round keys from the original key (key schedule)
 * - pkcs7_pad: Adds padding to data using the PKCS7 padding scheme
 * - pkcs7_unpad: Removes padding from data using the PKCS7 padding scheme
 * - xorBlock: XORs a block with the IV/round key.
 */

// S-Box construction: Take the multiplicative inverse in GF(2^8) of A_i
// followed by affine transformation to get B_i.
const byte sBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// Inverse S-Box construction: Apply the inverse affine transformation of B_i
// followed by multiplicative inverse in GF(2^8) to get A_i.
const byte inv_sBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                          0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Galois Field (2^8) multiplication
 * Used in MixColumns/InvMixColumns transformations
 * Implemented using the standard shift-and-add algorithm
 */
byte gf_mul(byte a, byte b) {
  byte ret = 0;
  byte msb = 0;
  for (uint8_t i = 0; i < 8; ++i) {
    if (b & 1)
      ret ^= a;
    msb = a & 0x80;
    a <<= 1;
    byte mask = -(msb == 0x80);
    a ^= (0x1b & mask);
    b >>= 1;
  }
  return ret;
}

std::vector<byte> generate16bytes() {
  std::vector<byte> randNum(16);

#ifdef _WIN32  // for windows system
  if (RAND_bytes(randNum.data(), 16) != 1)
    throw std::runtime_error("Failed to generate random bytes");

#else  // for unix system
  FILE *file = fopen("/dev/urandom", "rb");
  if (file == NULL)
    throw std::runtime_error("Failed to open /dev/urandom");

  if (fread(randNum.data(), 1, 16, file) != 16)
    throw std::runtime_error("Failed to read from /dev/urandom");

  fclose(file);
#endif
  return randNum;
}

/*
 * AES-128 key expansion routine
 * Generates 11 round keys (176 bytes) from the initial 16-byte key
 * Round keys are stored consecutively: k0|k1|k2|...|k10
 */
uint32_t g_func(uint32_t word, int round);

void keySchedule(const std::vector<byte> &key_0, std::vector<byte> &roundKey) {
  // Add first key, k_0
  std::vector<uint32_t> keys;
  keys.reserve(44);
  for (uint8_t i = 0; i < key_0.size(); i += 4) {
    keys.push_back((uint32_t)(key_0[i] << 24) | (uint32_t)(key_0[i + 1] << 16) |
                   (uint32_t)(key_0[i + 2] << 8) | (uint32_t)(key_0[i + 3]));
  }
  keys.resize(44);

  for (uint8_t i = 1; i <= 10; ++i) {
    keys[4 * i] = keys[4 * (i - 1)] ^ g_func(keys[4 * i - 1], i);  // first word
    for (uint8_t j = 1; j <= 3; ++j) {
      keys[4 * i + j] =
          keys[4 * i + j - 1] ^ keys[4 * (i - 1) + j];  // other words
    }
  }

  roundKey.resize(4 * keys.size());
  for (size_t i = 0; i < keys.size(); ++i) {
    roundKey[4 * i] = (keys[i] >> 24) & 0xff;
    roundKey[4 * i + 1] = (keys[i] >> 16) & 0xff;
    roundKey[4 * i + 2] = (keys[i] >> 8) & 0xff;
    roundKey[4 * i + 3] = keys[i] & 0xff;
  }
  std::memset(keys.data(), 0, keys.size() * sizeof(uint32_t));
}

uint32_t g_func(uint32_t word, int round) {
  // Round coefficient values
  const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                            0x20, 0x40, 0x80, 0x1b, 0x36};
  word = (word << 8) | (word >> 24);  // ROL word

  word = (((uint32_t)(sBox[(word >> 24) & 0xff]) ^ (uint32_t)rcon[round - 1])
          << 24) |
         ((uint32_t)sBox[(word >> 16) & 0xff] << 16) |
         ((uint32_t)sBox[(word >> 8) & 0xff] << 8) |
         ((uint32_t)sBox[(word) & 0xff]);

  return word;
}

void pkcs7_pad(std::vector<byte> &input, const size_t filesize) {
  size_t pad_len = 16 - (filesize % 16);
  for (size_t i = filesize; i < filesize + pad_len; ++i) {
    input[i] = static_cast<byte>(pad_len);
  }
}

void pkcs7_unpad(std::vector<byte> &input, bool test_mode) {
  if (test_mode)
    return;

  if (input.empty())
    throw std::runtime_error("Empty input");

  uint8_t pad_len = input.back();
  if (pad_len < 1 || pad_len > 16)
    throw std::runtime_error("Invalid padding length");
  for (size_t i = 1; i <= pad_len; ++i) {
    if (input[input.size() - i] != (byte)pad_len)
      throw std::runtime_error("Invalid padding bytes");
  }
  input.erase(input.end() - pad_len, input.end());
}

void xorBlock(byte *curr_state, const byte *block) {
  for (uint8_t i = 0; i < 16; ++i) {
    curr_state[i] ^= block[i];
  }
}

/*
 * Encryption functions start here:
 * - byteSub: Substitutes bytes using the sBox
 * - shiftRows: Shifts rows in the state
 * - mixColumns: Mixes columns for diffusion
 * - enc_aes_128_cbc: AES encryption in CBC mode
 */

void byteSub(byte state[], size_t state_size) {
  for (uint8_t i = 0; i < state_size; ++i) {
    // state[i] = sBox[((state[i] & 0xf0) >> 4) * 16 + (state[i] & 0x0f)];  //
    // Textbook method
    state[i] = sBox[state[i]];  // direct indexing
  }
}

void shiftRows(byte state[]) {
  /*
    [b0 b4 b8  b12]    [b0  b4  b8  b12]
    [b1 b5 b9  b13] => [b5  b9  b13 b1 ]
    [b2 b6 b10 b14] => [b10 b14 b2  b6 ]
    [b3 b7 b11 b15] => [b15 b3  b7  b11]
   */

  // Row 1: shift left by 1
  byte temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  // Row 2: shift left by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  // Row 3: shift left by 3
  temp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = temp;
}

void mixColumns(byte state[], size_t state_size) {
  /*
   * Matrix multiplication in GF(2^8):
   * [c0]   [2 3 1 1] [b0]
   * [c1] = [1 2 3 1] [b1]
   * [c2]   [1 1 2 3] [b2]
   * [c3]   [3 1 1 2] [b3]
   */
  byte c[4];
  for (uint8_t i = 0; i < state_size; i += 4) {
    c[0] = gf_mul(state[i], 0x02) ^ gf_mul(state[i + 1], 0x03) ^ state[i + 2] ^
           state[i + 3];
    c[1] = state[i] ^ gf_mul(state[i + 1], 0x02) ^ gf_mul(state[i + 2], 0x03) ^
           state[i + 3];
    c[2] = state[i] ^ state[i + 1] ^ gf_mul(state[i + 2], 0x02) ^
           gf_mul(state[i + 3], 0x03);
    c[3] = gf_mul(state[i], 0x03) ^ state[i + 1] ^ state[i + 2] ^
           gf_mul(state[i + 3], 0x02);

    state[i] = c[0];
    state[i + 1] = c[1];
    state[i + 2] = c[2];
    state[i + 3] = c[3];
  }
}

/*
 * AES-128-CBC encryption
 * Processes plaintext in 16-byte blocks using CBC mode
 * Returns the length of ciphertext (including padding)
 *
 * Encryption sequence per block:
 * 1. PKCS7 padding
 * 2. CBC mode XOR
 * 3. 10 rounds of: SubBytes->ShiftRows->MixColumns(except last
 * round)->AddRoundKey
 */
int enc_aes_128_cbc(std::vector<byte> &buffer, size_t og_filesize,
                    const std::vector<byte> &key, const std::vector<byte> &iv,
                    std::vector<byte> &ciphertext) {
  if (key.empty() || key.size() != 16)
    throw std::invalid_argument("Error: Invalid key!");

  // Calculate plaintext size and preallocate memory
  const size_t num_blocks = buffer.size() / 16;
  pkcs7_pad(buffer, og_filesize);  // pad the input

  std::vector<byte> roundKeys;  // For 11 round keys
  roundKeys.reserve(176);       // 11 * 16 bytes
  keySchedule(key, roundKeys);  // Generate 10 round keys

  ciphertext.resize(buffer.size());  // preallocation for ciphertext

  const byte *pt_ptr = buffer.data();
  const byte *rk_ptr = roundKeys.data();
  byte *ct_ptr = ciphertext.data();

  byte curr_state[16];
  byte prev_state[16];

  for (size_t block = 0; block < num_blocks; ++block) {
    memcpy(curr_state, pt_ptr + (block * 16),
           16);  // load plaintext block as current state

    // CBC mode operations
    if (block == 0)
      xorBlock(curr_state, iv.data());
    else
      xorBlock(curr_state, prev_state);

    const byte *curr_key = key.data();
    xorBlock(curr_state, curr_key);  // key whitening with key_0

    for (uint8_t round = 1; round <= 10; ++round) {
      curr_key = rk_ptr + (round * 16);
      byteSub(curr_state, 16);
      shiftRows(curr_state);
      if (round != 10) {
        mixColumns(curr_state, 16);
      }
      xorBlock(curr_state, curr_key);
    }
    memcpy(prev_state, curr_state, 16);
    memcpy(ct_ptr + (block * 16), curr_state, 16);
  }
  std::memset(curr_state, 0, sizeof(curr_state));
  std::memset(prev_state, 0, sizeof(prev_state));
  return ciphertext.size();
}

/*
 * Decryption functions start here:
 * - invByteSub: Inverse substitution using the inv_sBox
 * - invShiftRows: Reverses the row shifts in the state
 * - invMixColumns: Inverse mixing of columns for decryption
 * - dec_aes_128_cbc: AES decryption in CBC mode
 */

void invByteSub(byte state[], size_t state_size) {
  for (uint8_t i = 0; i < state_size; ++i) {
    state[i] = inv_sBox[state[i]];
  }
}

void invShiftRows(byte state[]) {
  /*
    [B0 B4 B8  B12]    [B0  B4  B8  B12]
    [B1 B5 B9  B13] => [B5  B9  B13 B1 ]
    [B2 B6 B10 B14] => [B10 B14 B2  B6 ]
    [B3 B7 B11 B15] => [B15 B3  B7  B11]
   */

  // Row 1: shift right by 1
  byte temp = state[1];
  state[1] = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = temp;

  // Row 2: shift right by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  // Row 3: shift right by 3
  temp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = temp;
}

void invMixColumns(byte state[], size_t state_size) {
  byte b[4];
  for (uint8_t i = 0; i < state_size; i += 4) {
    b[0] = gf_mul(state[i], 0x0e) ^ gf_mul(state[i + 1], 0x0b) ^
           gf_mul(state[i + 2], 0x0d) ^ gf_mul(state[i + 3], 0x09);
    b[1] = gf_mul(state[i], 0x09) ^ gf_mul(state[i + 1], 0x0e) ^
           gf_mul(state[i + 2], 0x0b) ^ gf_mul(state[i + 3], 0x0d);
    b[2] = gf_mul(state[i], 0x0d) ^ gf_mul(state[i + 1], 0x09) ^
           gf_mul(state[i + 2], 0x0e) ^ gf_mul(state[i + 3], 0x0b);
    b[3] = gf_mul(state[i], 0x0b) ^ gf_mul(state[i + 1], 0x0d) ^
           gf_mul(state[i + 2], 0x09) ^ gf_mul(state[i + 3], 0x0e);
    state[i] = b[0];
    state[i + 1] = b[1];
    state[i + 2] = b[2];
    state[i + 3] = b[3];
  }
}

int dec_aes_128_cbc(const std::vector<byte> &key, const std::vector<byte> &iv,
                    const std::vector<byte> &ciphertext,
                    std::vector<byte> &decryptedtext, int ciphertext_len,
                    bool test_mode) {
  if (key.empty() || key.size() != 16)
    throw std::invalid_argument("Error: Invalid key!");

  if (iv.empty() || iv.size() != 16)
    throw std::invalid_argument("Error: Invalid IV!");

  if (ciphertext_len % 16 != 0)
    throw std::runtime_error("Error: Invalid ciphertext length!");

  size_t num_block = ciphertext_len / 16;
  decryptedtext.resize(ciphertext_len);  // preallocate decrypt text

  // generate round keys
  std::vector<byte> roundKeys;
  roundKeys.reserve(176);
  keySchedule(key, roundKeys);

  const byte *ct_ptr = ciphertext.data();
  const byte *rk_ptr =
      roundKeys.data() + roundKeys.size();  // start decryption from key_10
  const byte *curr_key = nullptr;
  byte *dt_ptr = decryptedtext.data();

  byte curr_state[16];
  byte prev_state[16];

  for (size_t block = 0; block < num_block; ++block) {
    memcpy(curr_state, ct_ptr + (block * 16), 16);

    for (uint8_t round = 1; round <= 10; ++round) {
      curr_key = rk_ptr - (16 * round);
      xorBlock(curr_state, curr_key);
      if (round != 1)
        invMixColumns(curr_state, 16);

      invShiftRows(curr_state);
      invByteSub(curr_state, 16);
    }
    xorBlock(curr_state, key.data());  // key whitening with key_0

    // CBC mode operations
    if (block == 0)
      xorBlock(curr_state, iv.data());
    else {
      memcpy(prev_state, ct_ptr + ((block - 1) * 16), 16);
      xorBlock(curr_state, prev_state);
    }

    memcpy(dt_ptr + (block * 16), curr_state, 16);
  }

  std::memset(curr_state, 0, sizeof(curr_state));
  std::memset(prev_state, 0, sizeof(prev_state));

  pkcs7_unpad(decryptedtext, test_mode);  // remove padding from plaintext
  return decryptedtext.size();
}

/*
int main()
{
  std::string str = "Hi! I'm Om, and this is my AES-128-CBC implementation.";

  std::vector<byte> key = generate16bytes();
  std::vector<byte> iv = generate16bytes();

  std::vector<byte> ciphertext, decryptedtext;
  int ct_len = enc_aes_128_cbc(str, key, iv, ciphertext);
  int dt_len = dec_aes_128_cbc(key, iv, ciphertext, decryptedtext, ct_len);

  std::string dec = std::string(decryptedtext.begin(), decryptedtext.end());
  std::ofstream file("msg.txt", std::ios::out);
  file << "Decrypted text:\n"
       << dec;
  file.close();
  return 0;
}
*/