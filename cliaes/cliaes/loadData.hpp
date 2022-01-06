#ifndef CLIAES_LOAD_DATA_HPP
#define CLIAES_LOAD_DATA_HPP

#include <string>

#include <libaes/types.hpp>

dword_t getFileSize(std::string path);
byte_t* loadDataFromFile(std::string path, word_t bufferSize);
bool writeEncryptedDataToFile(std::string path, byte_t* data, word_t size);

#endif
