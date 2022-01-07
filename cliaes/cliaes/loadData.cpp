#include <string>
#include <iostream>
#include <fstream>

#include <libaes/types.hpp>

unsigned int getFileSize(std::string path)
{
    std::streampos fileSize = 0;

    std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open())
    {
        fileSize = file.tellg();
        file.close();
    }

    return (unsigned int)fileSize;
}

byte_t* loadDataFromFile(std::string path, unsigned int bufferSize)
{
    std::streampos fileSize;
    byte_t* data = nullptr;

    std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open())
    {
        fileSize = file.tellg();
        data = new byte_t[bufferSize];
        if (data == nullptr)
            return nullptr;
        file.seekg(0, std::ios::beg);
        file.read((char*)data, fileSize);
        file.close();
    }

    return data;
}

bool writeEncryptedDataToFile(std::string path, byte_t* data, word_t size)
{
    std::ofstream file(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (file.is_open())
    {
        file.write((char*)data, size);
        file.close();
        return true;
    }

    return false;
}
