#include <libaes/libaes.hpp>
#include <libaes/types_helper.hpp>
#include <libaes/aes_cipher.hpp>
#include <iostream>
namespace AES
{

/**
 * Increment counter function, used for CTR and GCM only
**/
static inline void incCounter(qword_t& counter)
{
    qwordInc(counter);
}

/*****************************
 * ECB
 ****************************/
bool AES::ecb_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    qword_t state;

    unsigned int offsetData = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(QWTOBUF(state), dataIn + offsetData, AES::BLOCKSIZE);

        // Cipher state
        cipherBlock(QWTOBUF(state), ksch, this->Nr);

        memcpy(dataOut + offsetData, QWTOCBUF(state), AES::BLOCKSIZE);

        ++i;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

bool AES::ecb_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    qword_t state;

    unsigned int offsetData = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(QWTOBUF(state), dataIn + offsetData, AES::BLOCKSIZE);

        // Cipher state
        decipherBlock(QWTOBUF(state), ksch, this->Nr);

        memcpy(dataOut + offsetData, QWTOCBUF(state), AES::BLOCKSIZE);

        ++i;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

/*****************************
 * CBC
 ****************************/
bool AES::cbc_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    qword_t state;
    qword_t nonce;

    qwordCopy(this->iv, nonce);

    // Save init state to store at end of message
    memcpy(dataOut + dataSize, QWTOCBUF(nonce), AES::BLOCKSIZE);

    unsigned int offsetData = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(QWTOBUF(state), dataIn + offsetData, AES::BLOCKSIZE);

        qwordXor(state, nonce);

        // Cipher state
        cipherBlock(QWTOBUF(nonce), ksch, this->Nr);

        memcpy(dataOut + offsetData, QWTOCBUF(nonce), AES::BLOCKSIZE);

        ++i;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

bool AES::cbc_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    qword_t state;
    qword_t nonce;

    qwordCopy(dataIn + (dataSize - AES::BLOCKSIZE), nonce);

    unsigned int offsetData = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16 - 1; // Dont forget IV block
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(QWTOBUF(state), dataIn + offsetData, AES::BLOCKSIZE);

        // Cipher state
        decipherBlock(QWTOBUF(state), ksch, this->Nr);

        qwordXor(nonce, state);

        memcpy(dataOut + offsetData, QWTOCBUF(state), AES::BLOCKSIZE);

        memcpy(QWTOBUF(nonce), dataIn + offsetData, AES::BLOCKSIZE);

        ++i;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

/*****************************
 * CTR
 ****************************/
bool AES::ctr_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    qword_t state;
    qword_t counter;

    qwordCopy(this->iv, counter);

    // Save init state to store at end of message
    memcpy(dataOut + dataSize, QWTOCBUF(counter), AES::BLOCKSIZE);

    unsigned int offsetData = 0;
    unsigned int i = 0;
    unsigned int nBlocks = dataSize / 16;
    unsigned int lastBlock = dataSize % 16;
    unsigned int blockSize = AES::BLOCKSIZE;
    if (lastBlock != 0) {
        nBlocks++;
        if (nBlocks == 1) {
            blockSize = lastBlock;
        }
    }
    while (i < nBlocks)
    {
        // Init the state (AES input)
        qwordCopy(counter, state);

        // Update counter
        incCounter(counter);

        // Cipher state
        cipherBlock(QWTOBUF(state), ksch, this->Nr);

        qword_t plainBlock;
        memcpy(QWTOBUF(plainBlock), dataIn + offsetData, blockSize);
        qwordXor(plainBlock, state);

        memcpy(dataOut + offsetData, QWTOCBUF(state), blockSize);

        ++i;
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

bool AES::ctr_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    qword_t state;
    qword_t counter;

    qwordCopy(dataIn + (dataSize - AES::BLOCKSIZE), counter);

    unsigned int offsetData = 0;
    unsigned int i = 0;
    unsigned int nBlocks = dataSize / 16 - 1;
    unsigned int lastBlock = dataSize % 16;
    unsigned int blockSize = AES::BLOCKSIZE;
    if (lastBlock != 0) {
        nBlocks++;
        if (nBlocks == 1) {
            blockSize = lastBlock;
        }
    }
    while (i < nBlocks)
    {
        // Init the state (AES input)
        qwordCopy(counter, state);

        // Update counter
        incCounter(counter);

        // Cipher state
        cipherBlock(QWTOBUF(state), ksch, this->Nr);

        qword_t cipherBlock;
        memcpy(QWTOBUF(cipherBlock), dataIn + offsetData, blockSize);
        qwordXor(cipherBlock, state);

        memcpy(dataOut + offsetData, QWTOCBUF(state), blockSize);

        ++i;
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

} // namespace AES
