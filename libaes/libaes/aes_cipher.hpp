#ifndef LIBAES_AES_CIPHER_HPP
#define LIBAES_AES_CIPHER_HPP

#include <libaes/types.hpp>

namespace AES
{

class LOOKUPS
{
public:
    static const word_t RCON[];
    static const byte_t SBOX[];
    static const byte_t INV_SBOX[];
    static const byte_t MIX_COLUMNS_MATRIX[];
    static const byte_t INV_MIX_COLUMNS_MATRIX[];

    LOOKUPS() = delete;
    ~LOOKUPS() = delete;
    LOOKUPS(LOOKUPS& c) = delete;
    LOOKUPS(LOOKUPS&& c) = delete;
    LOOKUPS& operator=(LOOKUPS&& other) = delete;
};

void keyExpansion(const byte_t* key, word_t* ksch, int kschSize, int Nk);
void cipherBlock(byte_t* state, const word_t* keySchedule, int Nr);
void decipherBlock(byte_t* state, const word_t* keySchedule, int Nr);

} // namespace AES

#endif
