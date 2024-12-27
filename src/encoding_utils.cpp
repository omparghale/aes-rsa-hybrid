#include <iostream>
#include <string>
#include<bitset>
#include <vector>
#include <fstream>
#include <sstream>
#include "encoding_utils.h"

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
