#include <iostream>
#include <cstring>

#include <libaes/types.hpp>

int bitInByte(int bits)
{
    return bits / 8 + (bits % 8 == 0 ? 0 : 1);
}

int byteInBit(int bytes)
{
    return bytes * 8;
}

int bitInWord(int bits)
{
    return bits / 32 + (bits % 32 == 0 ? 0 : 1);
}

word_t bytesToWord(byte_t b1, byte_t b2, byte_t b3, byte_t b4)
{
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

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
        sprintf_s(buff, 3, "%02X", bytes[i]);
        buffer += std::string(buff);
    }

    return buffer;
}

std::string wordToHexString(word_t word)
{
    char buff[9];
    sprintf_s(buff, 9, "%08X", word);
    return std::string(buff);
}
