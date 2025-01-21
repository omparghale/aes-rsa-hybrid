# AES-RSA Hybrid Cryptosystem
> ⚠️ **Caution**: This project is for ***educational purposes only*** and is ***not*** suitable for production use.

## Overview
This project implements a hybrid encryption system combining:
* **AES (Advanced Encryption Standard)**: A symmetric encryption algorithm for efficient data encryption
* **RSA (Rivest-Shamir-Adleman)**: A widely-used asymmetric encryption algorithm
  
This project demonstrates the implementation of both AES and RSA from scratch in C++, built using fundamental cryptographic principles and mathematical concepts.

## Key Points
* **Not Production-Ready**: This implementation is designed as a learning exercise:
  - The RSA implementation uses a small 64-bit key size for simplicity and computational feasibility.
  - Real-world systems use much larger keys (e.g., 2048 or 4096 bits) and follow standards like ASN.1/DER for key storage.
  - The AES implementation, while following the standard, doesn't include protections against side-channel attacks.
* **Educational Objective**: The project demonstrates core cryptographic principles but does not aim to match the security or performance of industry-standard libraries

## Features

### AES Implementation from Scratch
- Complete AES-128-CBC mode implementation
- PKCS7 padding scheme
- Core AES operations:
  - SubBytes/InvSubBytes using pre-computed S-boxes
  - ShiftRows/InvShiftRows transformations
  - MixColumns/InvMixColumns using Galois Field arithmetic
  - Key expansion routine
- Validated against NIST test vectors (CBC mode)
- Secure random IV generation

### RSA Implementation from Scratch
- Key generation (public and private keys)
- PKCS#1 padding for secure encryption of small data (AES keys)
- Modular exponentiation and primality testing (Miller-Rabin)
- Extended Euclidean Algorithm (EEA) for modular inverses

### Hybrid Workflow
- AES encrypts the plaintext message for efficiency
- RSA encrypts the AES key for secure transmission
- Complete file-based workflow with:
  - Serialized key storage in PEM format
  - Binary storage for encrypted data
  - Structured file organization


## Compilation and Execution
### Prerequisites
* C++17 or later
* OpenSSL development libraries (used for SHA-256 hashing and secure random number generation)
  * **Linux**: Install with `sudo apt-get install libssl-dev`
  * **Windows**: Ensure OpenSSL is installed and available in your build environment

### Compilation
```bash
g++ -Iinclude src/*.cpp -o project -lcrypto -lssl -std=c++17
```
Run the program using:
- Windows: `./project.exe path/to/your/file`
- Linux: `./project path/to/your/file`<br>
example: `./project "test/sample.pdf"`

## Usage

### Encryption:
- Place any file you want to encrypt in the test directory
- The program works with any file format (tested with txt, mp4, xlsx, zip, h, pdf, png)
- When prompted, enter the path to your file

### Files Created:
- **AES-encrypted data**: `ciphertext/msg_enc.aes`
- **RSA-encrypted AES key**: `ciphertext/key_enc.bin`

### Decryption:
- Decrypted file is saved to `test/decrypted.<original_extension>`
- File integrity is verified using SHA-256 hash comparison
- Successful decryption is confirmed when original and decrypted file hashes match

### Logs:
- Detailed operation logs are saved in `logs/` directory
- Includes encryption/decryption status and hash verification results

## File Structure
```
.
├── include/              # Header files
│   ├── aes_util.h        # AES implementation headers
│   ├── rsa.h             # RSA core functionality
│   └── ...               # Other utility headers
├── src/                  # Source files
│   ├── aes.cpp           # AES implementation
│   ├── aes_openssl.cpp   # Alternative OpenSSL version (not used)
│   ├── rsa.cpp           # RSA implementation
│   └── ...               # Utility implementations
├── test/                 # Test files
│   ├── aes_nist_test.cpp # AES NIST vector testing
│   ├── *.rsp             # NIST test vector files
│   └── test_1.txt        # Sample input files
├── ciphertext/           # Encrypted outputs
├── keys/                 # RSA key storage
└── logs/                 # Operation logs
```

## References
- This project draws on concepts from *Understanding Cryptography* by Christof Paar and Jan Pelzl, an awesome resource for learning modern cryptographic fundamentals.
- Base64 encoding/decoding adapted from René Nyffenegger's implementation (http://renenyffenegger.ch/notes/development/Base64/)

## Conclusion
This project was inspired by a desire to learn the fundamentals of cryptography and create a meaningful personal project.Thank you for reviewing it, and I hope it serves as a useful introduction to the core principles of public key cryptography and hybrid encryption.
