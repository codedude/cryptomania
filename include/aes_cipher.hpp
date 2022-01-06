#ifndef AES_AES_CIPHER_HPP
#define AES_AES_CIPHER_HPP

#include "types.hpp"

namespace AES
{

    void keyExpansion(const byte_t *key, word_t *ksch, int kschSize, int Nk);
    void cipherBlock(byte_t *state, const word_t *keySchedule, int Nr);
    void decipherBlock(byte_t *state, const word_t *keySchedule, int Nr);

} // namespace AES

#endif
