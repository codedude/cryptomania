#include <iostream>
#include <cstring>

#include <boost/format.hpp>

#include "types.hpp"

void qwordToByteArray(qword_t input, byte_t* buffer)
{
    for (int i = 0; i < 16; ++i)
        buffer[i] = (byte_t)(input >> ((15 - i) * 8)) & 0xff;
}

qword_t byteArrayToQword(const byte_t* buffer, int size)
{
    qword_t n = 0;
    for (int i = 0; i < size; ++i)
        n = (n <<= 8) | buffer[i];
    return n;
}

std::string bytesToHexString(const byte_t* bytes, int byteSize)
{
    std::string buffer;

    for (int i = 0; i < byteSize; ++i)
    {
        char buff[3];
        sprintf(buff, "%02X", bytes[i]);
        buffer += std::string(buff);
    }

    return buffer;
}

std::string wordToHexString(word_t word)
{
    char buff[9];
    sprintf(buff, "%08X", word);
    return std::string(buff);
}

byte_t* stringToBytes(const std::string& str)
{
    byte_t* buffer = new byte_t[str.size() / 2];
    for (int i = 0; i < (int)str.size(); i += 2)
    {
        buffer[i / 2] = (std::stoi(std::string(1, str[i]), nullptr, 16) << 4) | (std::stoi(std::string(1, str[i + 1]), nullptr, 16));
    }
    return buffer;
}
