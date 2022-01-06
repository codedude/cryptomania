#ifndef LIBAES_TYPES_HELPER_HPP
#define LIBAES_TYPES_HELPER_HPP

#include <libaes/types.hpp>

int bitInByte(int bits);
int byteInBit(int bytes);
int bitInWord(int bits);
word_t bytesToWord(byte_t b1, byte_t b2, byte_t b3, byte_t b4);

void qwordToByteArray(qword_t input, byte_t* buffer);
qword_t byteArrayToQword(const byte_t* buffer, int size);

std::string bytesToHexString(const byte_t* bytes, int byteSize);
std::string wordToHexString(word_t word);


#endif
