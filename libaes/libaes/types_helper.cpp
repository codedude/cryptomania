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

void qwordCopy(const qword_t& from, qword_t& to)
{
    memcpy(QWTOBUF(to), QWTOBUF(from), sizeof(qword_t));
}

void qwordCopy(const byte_t* from, qword_t& to)
{
    memcpy(QWTOBUF(to), from, sizeof(qword_t));
}

void qwordCopy(const qword_t& from, byte_t* to)
{
    memcpy(to, QWTOBUF(from), sizeof(qword_t));
}

void qwordCopy(const byte_t* from, byte_t* to)
{
    memcpy(to, from, sizeof(qword_t));
}

// xor = dont care of byte swipping
void qwordXor(const qword_t& q1, qword_t& q2)
{
    for (int i = 0; i < 16; ++i)
        q2.b[i] ^= q1.b[i];
}

// https://github.com/openssl/openssl/blob/master/crypto/modes/ctr128.c
void qwordInc(qword_t& q1)
{
    int n = 16;
    word_t carry = 1;
    do {
        --n;
        carry += q1.b[n];
        q1.b[n] = (byte_t)carry;
        carry >>= 8;
    } while (carry && n);
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
