#ifndef RSA_UTIL_H
#define RSA_UTIL_H

#include <random>
#include <cstdint>
#include <iostream>
// #include<stdexcept>

bool primality_check(uint64_t num);
bool coprimality_check(uint64_t e, uint64_t phi);
int64_t eea_coeff(int64_t a, int64_t b);
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod);
uint64_t prime_num_gen();
uint64_t mod_inv(uint64_t a, uint64_t n);
uint64_t totient(uint64_t p, uint64_t q);

#endif