#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdint>
#include "encoding_utils.h"

const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string int2base64(uint64_t num)
{
  if(num==0)
    return "A===";
  std::string base64_str;
  std::string binary = std::bitset<64ULL>(num).to_string(); // convert uint6_t to binary string
  while (binary.at(0) != '1')
  {
    binary.erase(binary.begin()); // erase leading 0s
  }
  int len = binary.length();
  int r = len % 6;
  if(r>0)
    binary.append(6 - r, '0');

  len = binary.length();

  int pad_tok = (len / 6) % 4 != 0 ? 4 - ((len / 6) % 4) : 0;
  for (int i = 0; i < len;i += 6)
  {
    uint64_t intermediate = std::strtoull(binary.substr(i, 6).c_str(), 0, 2);
    base64_str += base64_chars[intermediate];
  }
  
  base64_str.append(pad_tok, '=');

  return base64_str;
}

// Converts a ASCII value to string
std::string ascii2text_str(uint64_t num)
{
  std::string temp = std::to_string(num);
  std::string res;

  for (int i = 0; i < temp.length();)
  {
    try
    {
      if (i + 2 <= temp.length() &&
          std::stoi(temp.substr(i, 2)) < 99 &&
          std::stoi(temp.substr(i, 2)) >= 32)
      {
        res += static_cast<char>(std::stoi(temp.substr(i, 2)));
        i += 2;
      }
      else if (i + 3 <= temp.length() &&
               std::stoi(temp.substr(i, 3)) >= 100 &&
               std::stoi(temp.substr(i, 3)) <= 255)
      {
        res += static_cast<char>(std::stoi(temp.substr(i, 3)));
        i += 3;
      }
      else
      {
        throw std::invalid_argument("Invalid ascii code");
      }
    }
    catch (const std::exception &e)
    {
      std::cerr << "Error: " << e.what() << std::endl;
      return "";
    }
  }
  return res;
}

// Converts a file from ASCII to text
std::string ascii2text_str_file_read(const std::string &path, char delimeter)
{
  std::string result, line;
  std::ifstream f(path);

  if (!f.is_open())
  {
    std::cerr << "Error opening the file!";
    return "";
  }

  while (std::getline(f, line))
  {
    result += line + "\n";
  }

  f.close();

  std::vector<int> tokens;
  std::stringstream ss(result);
  std::string token;

  while (std::getline(ss, token, delimeter)) // delimeter = " "
  {
    tokens.push_back(stoi(token));
  }

  std::string output;

  for (const auto &word : tokens)
  {
    output += (char)word;
  }

  return output;
}

std::string text2ascii_str(std::string s)
{
  std::string res;
  for (int i = 0; i < s.length(); i++)
  {
    res += std::to_string((int)s[i]);
  }
  return res;
}

uint64_t text2ascii_int(std::string s)
{
  s = text2ascii_str(s);
  return std::strtoull(s.c_str(), NULL, 0);
}

// std::string ans = std::bitset<128>(65110117115104107).to_string();
// while (ans.at(0) != '1')
// {
//   ans.erase(ans.begin());
// }
