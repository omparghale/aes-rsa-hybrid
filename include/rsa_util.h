#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <random>
#include <cstdint>
#include <iostream>
#include <stdexcept>

// Checks if a number is prime(Miller-Rabin test)
bool primality_check(uint64_t num);  

// Checks if two numbers are coprime
bool coprimality_check(uint64_t e, uint64_t phi);

// Computes coefficients for modular inverse (Extended Euclidean Algorithm)
int64_t eea_coeff(int64_t a, int64_t b);

// Fast modular exponentiation: (base ^ exp) % mod
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod);

// Generates a random prime number
uint64_t prime_num_gen();

// Computes the modular inverse of a modulo n
uint64_t mod_inv(uint64_t a, uint64_t n);

// Computes Euler's totient function ϕ(n)
uint64_t totient(uint64_t p, uint64_t q);

#endif