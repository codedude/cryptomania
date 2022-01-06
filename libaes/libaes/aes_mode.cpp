#include <libaes/libaes.hpp>
#include <libaes/types_helper.hpp>
#include <libaes/aes_cipher.hpp>

namespace AES
{
/**
 * Increment counter function, used for CTR and GCM only
**/
static inline void incCounter(qword_t& counter)
{
    counter += 1;
}

/*****************************
 * ECB
 ****************************/

bool AES::ecb_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    byte_t state[AES::BLOCKSIZE];

    unsigned int offsetDataIn = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(state, dataIn + offsetDataIn, AES::BLOCKSIZE);

        // Cipher state
        cipherBlock(state, ksch, this->Nr);

        memcpy(dataOut + offsetDataIn, state, AES::BLOCKSIZE);

        ++i;
        offsetDataIn += AES::BLOCKSIZE;
    }

    return true;
}

bool AES::ecb_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize)
{
    const word_t* ksch = this->keySchedule.keys;
    byte_t state[AES::BLOCKSIZE];

    unsigned int offsetDataIn = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(state, dataIn + offsetDataIn, AES::BLOCKSIZE);

        // Cipher state
        decipherBlock(state, ksch, this->Nr);

        memcpy(dataOut + offsetDataIn, state, AES::BLOCKSIZE);

        ++i;
        offsetDataIn += AES::BLOCKSIZE;
    }

    return true;
}

/*****************************
 * CBC
 ****************************/
bool AES::cbc_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize)
{
    const word_t* ksch = this->keySchedule.keys;
    byte_t state[AES::BLOCKSIZE];
    byte_t nonceBlock[AES::BLOCKSIZE];
    qword_t nonce;

    nonce = byteArrayToQword(iv, AES::BLOCKSIZE);

    // Save init state to store at end of message
    byte_t nonceBuffer[AES::BLOCKSIZE];
    qwordToByteArray(nonce, nonceBuffer);
    memcpy(nonceBlock, nonceBuffer, AES::BLOCKSIZE);

    unsigned int offsetDataIn = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(state, dataIn + offsetDataIn, AES::BLOCKSIZE);
        qword_t txtXorNonce = byteArrayToQword(state, AES::BLOCKSIZE);
        txtXorNonce ^= byteArrayToQword(nonceBlock, AES::BLOCKSIZE);
        qwordToByteArray(txtXorNonce, state);

        // Cipher state
        cipherBlock(state, ksch, this->Nr);

        memcpy(dataOut + offsetDataIn, state, AES::BLOCKSIZE);
        memcpy(nonceBlock, state, AES::BLOCKSIZE);

        ++i;
        offsetDataIn += AES::BLOCKSIZE;
    }

    memcpy(dataOut + dataSize, nonceBuffer, AES::BLOCKSIZE);
    return true;
}

bool AES::cbc_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize)
{
    const word_t* ksch = this->keySchedule.keys;
    byte_t state[AES::BLOCKSIZE];
    byte_t nonceBlock[AES::BLOCKSIZE];

    qword_t nonce = byteArrayToQword(dataIn + dataSize - AES::BLOCKSIZE, AES::BLOCKSIZE);

    qwordToByteArray(nonce, nonceBlock);

    unsigned int offsetDataIn = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16 - 1; // Dont forget IV block
    while (i < nBlocks)
    {
        // Init the state (AES input)
        memcpy(state, dataIn + offsetDataIn, AES::BLOCKSIZE);

        // Cipher state
        decipherBlock(state, ksch, this->Nr);

        qword_t txtXorNonce = byteArrayToQword(state, AES::BLOCKSIZE);
        txtXorNonce ^= byteArrayToQword(nonceBlock, AES::BLOCKSIZE);
        qwordToByteArray(txtXorNonce, state);

        memcpy(dataOut + offsetDataIn, state, AES::BLOCKSIZE);

        memcpy(nonceBlock, dataIn + offsetDataIn, AES::BLOCKSIZE);

        ++i;
        offsetDataIn += AES::BLOCKSIZE;
    }

    return true;
}

/*****************************
 * CTR
 ****************************/
bool AES::ctr_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize)
{
    const word_t* ksch = this->keySchedule.keys;
    byte_t state[AES::BLOCKSIZE];
    qword_t counter;

    counter = byteArrayToQword(iv, ivSize);

    // Save init state to store at end of message
    byte_t counterBuffer[AES::BLOCKSIZE];
    qwordToByteArray(counter, counterBuffer);

    unsigned int offsetDataIn = 0;
    unsigned int i = 0;
    unsigned int nBlocks = dataSize / 16;
    unsigned int lastBlock = dataSize % 16;
    if (lastBlock != 0)
        nBlocks++;
    unsigned int blockSize = AES::BLOCKSIZE;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        qwordToByteArray(counter, state);

        // Update counter
        incCounter(counter);

        // Cipher state
        cipherBlock(state, ksch, this->Nr);

        // XOR block_out + block_message and store in data_out
        qword_t stateBlock = byteArrayToQword(state, blockSize);
        qword_t plainBlock = byteArrayToQword(dataIn + offsetDataIn, blockSize);
        qword_t cipherBlock = stateBlock ^ plainBlock;
        qwordToByteArray(cipherBlock, state);
        memcpy(dataOut + offsetDataIn, state + (AES::BLOCKSIZE - blockSize), blockSize);

        ++i;
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetDataIn += AES::BLOCKSIZE;
    }

    memcpy(dataOut + dataSize, counterBuffer, AES::BLOCKSIZE);
    return true;
}

bool AES::ctr_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize)
{
    const word_t* ksch = this->keySchedule.keys;
    byte_t state[AES::BLOCKSIZE];
    qword_t counter;

    counter = byteArrayToQword(dataIn + dataSize - AES::BLOCKSIZE, AES::BLOCKSIZE);

    unsigned int offsetDataIn = 0;
    unsigned int i = 0;
    unsigned int nBlocks = dataSize / 16 - 1;
    unsigned int lastBlock = dataSize % 16;
    if (lastBlock != 0)
        nBlocks++;
    unsigned int blockSize = AES::BLOCKSIZE;
    while (i < nBlocks)
    {
        // Init the state (AES input)
        qwordToByteArray(counter, state);

        // Update counter
        incCounter(counter);

        // Cipher state
        cipherBlock(state, ksch, this->Nr);

        // XOR block_out + block_message and store in data_out
        qword_t stateBlock = byteArrayToQword(state, blockSize);
        qword_t cipherBlock = byteArrayToQword(dataIn + offsetDataIn, blockSize);
        qword_t plainBlock = stateBlock ^ cipherBlock;
        qwordToByteArray(plainBlock, state);
        memcpy(dataOut + offsetDataIn, state + (AES::BLOCKSIZE - blockSize), blockSize);

        ++i;
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetDataIn += AES::BLOCKSIZE;
    }

    return true;
}

/*****************************
 * GCM
 ****************************/
bool AES::gcm_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize)
{

    return true;
}
bool AES::gcm_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize)
{

    return true;
}

} // namespace AES
