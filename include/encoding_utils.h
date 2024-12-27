#ifndef ENCODING_UTILS_H
#define ENCODING_UTILS_H

#include <vector>
#include <string>
#include<bitset>


std::string ascii2text_str(uint64_t num);
std::string ascii2text_str_file_read(const std::string &path, char delimeter);
std::string text2ascii_str(std::string s);
uint64_t text2ascii_int(std::string s);

#endif


