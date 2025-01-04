#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <cctype>
#include <ctime>
#include <filesystem>
#include "encoding_utils.h"
typedef unsigned char byte;

// Checks if a file exists.
bool fileExists(const std::string &filename);

// Read file content into a string
std::string getFileContent(const std::string &filename);

// Write an RSA keys(public or private) in Base64 format
void writeKey(const std::string &filename, uint64_t mod, uint64_t key, const std::string &type);

// Read an RSA key from a file
void readKey(const std::string &filename, uint64_t &mod, uint64_t &key);

// Write RSA ciphertext to a binary file
void writeRsaCiphertext(const std::string &filename,
                        const std::vector<uint64_t> &ciphertext);

// Write AES ciphertext and IV to a binary file
void writeAesCipherText(const std::string &filename, const std::vector<byte> &iv, const std::vector<byte> &ciphertext);

// Read AES ciphertext and IV from a binary file
void readCiphertextIV(const std::string &filename, std::vector<byte> &iv, std::vector<byte> &ciphertext);

// Write decrypted plaintext to a file
void writeDecrytedMsg(const std::string &filename, const std::string &str);

// Get the current date or time as a string
inline std::string getDateTime(const std::string &s)
{
  time_t now = std::time(0);
  struct tm tstruct;
  char buf[80];
  tstruct = *localtime(&now);
  if (s == "now")
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
  else if (s == "date")
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
  return std::string(buf);
};

// Log a message with a timestamp
inline void Logger(std::string logMsg)
{
  std::string filePath = "logs/log_" + getDateTime("date") + ".txt";
  std::string now = getDateTime("now");
  std::ofstream f(filePath.c_str(), std::ios::out | std::ios::app);
  f << now << '\t' << logMsg << "\n";
  f.close();
}

// Clears the current day's log file
inline void rmFile()
{
  std::string filename = "logs/log_" + getDateTime("date") + ".txt";
  std::ofstream f;
  f.open(filename, std::ios::out | std::ios::trunc);
  f.close();
}

#endif // FILE_UTILS_H