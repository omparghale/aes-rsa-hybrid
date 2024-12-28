/*
  This file uses OpenSSL's implementation of SHA-256 for secure hashing.

  Writing a hash function from scratch, like MD5 or SHA-1, wouldn't 
  meet modern security standards, so OpenSSL ensures strong password 
  and key hashing. 

  OpenSSL's SHA-256 is an industry-standard cryptographic hash function 
  with strong guarantees like collision and preimage resistance.It allows 
  this project to focus on from-scratch implementations (e.g., RSA) while 
  maintaining real-world security for sensitive operations.
  
 */

#include <iostream>
#include <cstdint>
#