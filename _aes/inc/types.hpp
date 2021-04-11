#ifndef TYPES_HPP
#define TYPES_HPP

#include <cstdint>

#include <boost/multiprecision/cpp_int.hpp>

using qword_t = boost::multiprecision::uint128_t;
using dword_t = uint64_t;
using word_t = uint32_t;
using byte_t = uint8_t;

inline int bitInByte(int bits);
inline int byteInBit(int bytes);
inline int bitInWord(int bits);
inline word_t bytesToWord(byte_t b1, byte_t b2, byte_t b3, byte_t b4);

void qwordToByteArray(qword_t input, byte_t *buffer);
qword_t byteArrayToQword(const byte_t *buffer, int size);

std::string bytesToHexString(const byte_t *bytes, int byteSize);
std::string wordToHexString(word_t word);
byte_t *stringToBytes(const std::string &str);

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

#endif
