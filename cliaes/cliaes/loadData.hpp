#ifndef CLIAES_LOAD_DATA_HPP
#define CLIAES_LOAD_DATA_HPP

#include <string>

#include <libaes/types.hpp>

unsigned int getFileSize(std::string path);
byte_t* loadDataFromFile(std::string path, unsigned int bufferSize);
bool writeEncryptedDataToFile(std::string path, byte_t* data, unsigned int size);

#endif
