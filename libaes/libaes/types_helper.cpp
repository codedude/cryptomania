#include <cstring>
#include <string>

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

void copyUIntToBuf(unsigned int i, byte_t* buffer)
{
    buffer[3] = (byte_t)((i >> 0) & 0xff);
    buffer[2] = (byte_t)((i >> 8) & 0xff);
    buffer[1] = (byte_t)((i >> 16) & 0xff);
    buffer[0] = (byte_t)((i >> 24) & 0xff);
}

void qwordZero(qword_t& q)
{
    memset(QWTOBUF(q), 0, sizeof(qword_t));
}

void qwordCopy(const qword_t& from, qword_t& to)
{
    memcpy(QWTOBUF(to), QWTOCBUF(from), sizeof(qword_t));
}

void qwordCopy(const byte_t* from, qword_t& to)
{
    memcpy(QWTOBUF(to), from, sizeof(qword_t));
}

void qwordCopy(const qword_t& from, byte_t* to)
{
    memcpy(to, QWTOCBUF(from), sizeof(qword_t));
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

void qwordShiftRight(qword_t& q1)
{
    byte_t carry = 0;
    byte_t tmp;
    for (int i = 0; i < 16; ++i) {
        tmp = q1.b[i];
        q1.b[i] = (tmp >> 1) | carry;
        carry = (tmp & 0b01) << 7;
    }
}

void qwordShiftLeft(qword_t& q1)
{
    byte_t carry = 0;
    byte_t tmp;
    for (int i = 15; i >= 0; --i) {
        tmp = q1.b[i];
        q1.b[i] = (tmp << 1) | carry;
        carry = (tmp & 0b10000000) >> 7;
    }
}

// https://github.com/openssl/openssl/blob/master/crypto/modes/ctr128.c
void qwordInc(qword_t& q1, int nBytes)
{
    int i = 15;
    word_t carry = 1;
    do {
        --nBytes;
        carry += q1.b[i];
        q1.b[i] = (byte_t)carry;
        carry >>= 8;
        --i;
    } while (nBytes);
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
