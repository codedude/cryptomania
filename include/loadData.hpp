#ifndef LOADDATA_HPP
#define LOADDATA_HPP

#include <string>

#include "types.hpp"

dword_t getFileSize(std::string path);
byte_t *loadDataFromFile(std::string path, word_t bufferSize);
bool writeEncryptedDataToFile(std::string path, byte_t *data, word_t size);

#endif
