#include <random>
#include <cstdint>
#include "rsa_util.h"
// #include<iostream>

// Fast Binary Exponentiation: (base ^ exp) % mod
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod)
{
  // __uint128_t for intermediate calculations to prevent overflow
  __uint128_t b = base % mod;
  __uint128_t e = exp;
  __uint128_t m = mod;
  __uint128_t currVal = 1;

  int bit_length = 0;
  __uint128_t exp_dup = e;
  while (exp_dup != 0)
  {
    exp_dup >>= 1;
    bit_length += 1;
  }

  for (int i = bit_length - 1; i >= 0; --i)
  {
    currVal = (currVal * currVal) % m;
    if ((e >> i) & 1)
    {
      currVal = (currVal * b) % m;
    }
  }
  return (uint64_t)currVal;
}

// Miller-Rabin primality check
bool primality_check(uint64_t num)
{
  if (num <= 1)
    return false;
  if (num <= 3)
    return true;
  if (num % 2 == 0)
    return false;

  // decompose n-1 => d.2^m
  uint64_t m = 0;
  uint64_t d = num - 1;

  // Check divisors of n-1
  while (d % 2 == 0)
  {
    d /= 2;
    m++;
  }

  std::random_device rd;
  std::mt19937 generator(rd());
  std::uniform_int_distribution<uint64_t> dist(2, num - 2);

  int num_witness = 10;

  while (num_witness > 0)
  {
    num_witness--;
    uint64_t a = dist(generator); // base

    // b_0 = a^d (mod n)
    uint64_t b_0 = mod_exp(a, d, num);

    if (b_0 != 1 && b_0 != num - 1)
    {
      bool composite = true;
      for (int i = 0; i < m - 1; ++i)
      {

        // Square and reduce modulo num
        b_0 = (b_0 * b_0) % num;
        if (b_0 == 1)
          return false;
        else if (b_0 == num - 1)
        {
          composite = false;
          break;
        }
      }
      if (composite)
        return false;
    }
  }
  return true;
}

uint64_t prime_num_gen()
{
  std::random_device rdevice;  // seeding device
  std::mt19937 gen(rdevice()); // random number generator
  // Range => 2^30 to 2^31 - 1 => p.q => < 2^63
  std::uniform_int_distribution<uint64_t> dist((1ULL << 30), (1ULL << 31) - 1);

  uint64_t randNum;
  do
  {
    randNum = dist(gen) | 1;
  } while (!primality_check(randNum));
  return randNum;
}

// Eucledian Algorithm for coprimality check: => gcd(e,phi) = 1
bool coprimality_check(uint64_t e, uint64_t phi)
{
  while (e != 0 && phi != 0)
  {
    if (e > phi)
    {
      e = e % phi;
    }
    else
    {
      phi = phi % e;
    }
  }

  return (e == 1 || phi == 1);
}

// Extended Eucledian Algorithm :  computes coefficients x and y
// Satisfies a.x + b.y = gcd(a,b) for modular inverse compuation
int64_t eea_coeff(int64_t a, int64_t b)
{

  // standard EEA notation
  int64_t x, y, x_0 = 1, x_1 = 0, y_0 = 0, y_1 = 1, q = 1;
  while (a != 0 && b != 0)
  {
    if (a > b)
    {
      q = a / b;
      a = a % b;
    }
    else
    {
      q = b / a;
      b = b % a;
    }
    if (a == 0 || b == 0)
    {
      break;
    }

    x = x_0 - q * x_1;
    x_0 = x_1;
    x_1 = x;

    y = y_0 - q * y_1;
    y_0 = y_1;
    y_1 = y;
  }
  // std::cout << "x: " << x << " y: " << y;

  // a.a^-1 === 1 mod n
  // a^-1 = y for assumption: GCD(a,n) = 1
  return y;
}

uint64_t mod_inv(uint64_t a, uint64_t n)
{
  int64_t rawRes = eea_coeff(static_cast<int64_t>(a), static_cast<int64_t>(n)); // resultant coefficient might be negative

  // normalize to get non-negative coefficient [0,n-1]
  return static_cast<uint64_t>(
      ((rawRes % static_cast<int64_t>(n)) + static_cast<int64_t>(n)) % static_cast<int64_t>(n));
}

// Euler's totient function => ϕ(n) = (p-1)(q-1)
uint64_t totient(uint64_t p, uint64_t q)
{
  return (p - 1) * (q - 1);
}
