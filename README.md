# RSA and AES Hybrid Encryption System
## Overview
This project implements a hybrid encryption system combining:
* **RSA (Rivest-Shamir-Adleman)**: A widely-used asymmetric encryption algorithm.
* **AES (Advanced Encryption Standard)**: A symmetric encryption algorithm for efficient data encryption.
  
The primary goal of this project is educational, focusing on implementing RSA from scratch in C++ without relying on third-party cryptographic libraries for RSA. 
While AES uses OpenSSL for reliable symmetric encryption, RSA has been built using fundamental principles like modular arithmetic, primality testing, and PKCS#1 padding.
## Key Points
* **Not Production-Ready**: This implementation is designed as a learning exercise. It uses a small 64-bit RSA key size for simplicity and computational feasibility.
  Real-world systems use much larger keys (e.g., 2048 or 4096 bits) and follow standards like ASN.1/DER for key storage.
* **Educational Objective**: The project demonstrates core cryptographic principles but does not aim to match the security or performance of industry-standard libraries like OpenSSL or GMP.
---
## Features
### RSA Implementation from Scratch
- Key generation (public and private keys).
- PKCS#1-like padding for secure encryption of small data (AES keys).
- Modular exponentiation and primality testing (Miller-Rabin).
- Extended Euclidean Algorithm (EEA) for modular inverses.

### AES Encryption with OpenSSL
- AES-128-CBC for encrypting plaintext messages.
- Secure random key and IV generation.

### Hybrid Workflow
- AES encrypts the plaintext message for efficiency.
- RSA encrypts the AES key for secure transmission.

### File-Based Workflow
- RSA keys are stored in Base64-encoded `.pem` files for readability.
- Ciphertext and Initialization Vector (IV) are stored in binary files.

### Comprehensive Logging
- Logs encryption and decryption steps for transparency.
- ---
## Compilation and Execution
### Prerequisites
* **Linux**: Ensure `libssl-dev` is installed. You can install it with:  `sudo apt-get install libssl-dev`
* **Windows**: Ensure you have OpenSSL installed and available in your build environment
  
### Compilation
#### Windows
```bash
g++ -Iinclude src/*.cpp -o rsa_program -lcrypto -lssl
./rsa_program.exe
```
#### Linux
```bash
g++ -Iinclude src/*.cpp -o rsa_program -lcrypto -lssl
./rsa_program
```
---
## Usage

### Provide a Text File:
- Place a plaintext file (e.g., `test/test_1.txt`) in the project directory.
- When prompted, enter the path to the plaintext file.

### Encryption:
- The plaintext is encrypted using AES-128-CBC, and the AES key is encrypted using RSA.
- Encrypted files:
  - **AES-encrypted message**: `ciphertext/msg_enc.aes`.
  - **RSA-encrypted AES key**: `ciphertext/key_enc.bin`.

### Decryption:
- The program decrypts the RSA-encrypted AES key, then uses it to decrypt the AES-encrypted message.
- Decrypted file:
  - The original plaintext is saved to `test/decrypted.txt`.

### Logs:
- Logs for each run are saved in the `logs/` directory, e.g., `logs/log_<date>.txt`.
---
## File Structure
- `src/`: Contains the source files (`aes_util.cpp`, `rsa.cpp`, etc.).
- `include/`: Contains header files (`aes_util.h`, `rsa.h`, etc.).
- `test/`: Contains sample plaintext files and decrypted output.
- `ciphertext/`: Stores encrypted AES messages and RSA-encrypted keys.
- `keys/`: Stores Base64-encoded RSA keys (`pubKey.pem`, `privKey.pem`).
- `logs/`: Stores log files for process tracking.
---
## Reference
This project draws on concepts from *Understanding Cryptography* by Christof Paar and Jan Pelzl, an awesome resource for learning modern cryptographic fundamentals.
## Conclusion
This project was inspired by a desire to learn the fundamentals of cryptography and create a meaningful personal project. 
Thank you for reviewing it, and I hope it serves as a useful introduction to the core principles of public key cryptography and hybrid encryption.
