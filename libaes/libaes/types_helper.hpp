#ifndef LIBAES_TYPES_HELPER_HPP
#define LIBAES_TYPES_HELPER_HPP

#include <string>

#include <libaes/types.hpp>

int bitInByte(int bits);
int byteInBit(int bytes);
int bitInWord(int bits);
word_t bytesToWord(byte_t b1, byte_t b2, byte_t b3, byte_t b4);

std::string bytesToHexString(const byte_t* bytes, int byteSize);
std::string wordToHexString(word_t word);

void copyUIntToBuf(unsigned int i, byte_t* buffer);

void qwordZero(qword_t& q);
void qwordCopy(const qword_t& from, qword_t& to);
void qwordCopy(const byte_t* from, qword_t& to);
void qwordCopy(const qword_t& from, byte_t* to);
void qwordCopy(const byte_t* from, byte_t* to);
void qwordXor(const qword_t& q1, qword_t& q2);
void qwordShiftRight(qword_t& q1);
void qwordShiftLeft(qword_t& q1);
void qwordInc(qword_t& q1, int nBytes);

#endif
