#include <libaes/libaes.hpp>
#include <libaes/types_helper.hpp>
#include <libaes/aes_cipher.hpp>

#include <utility/logs.hpp>

namespace AES
{

/**
 * Increment counter function, used for CTR and GCM only
**/
static inline void incCounter(qword_t& counter)
{
    qwordInc(counter, 16);
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

    qwordCopy(this->iv, nonce);

    unsigned int offsetData = 0;
    unsigned int i = 0;
    const unsigned int nBlocks = dataSize / 16;
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

    qwordCopy(this->iv, counter);

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

        qword_t cBlock;
        memcpy(QWTOBUF(cBlock), dataIn + offsetData, blockSize);
        qwordXor(cBlock, state);

        memcpy(dataOut + offsetData, QWTOCBUF(state), blockSize);

        ++i;
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetData += AES::BLOCKSIZE;
    }

    return true;
}

// R = 0x10000111
// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
void gmul(const qword_t& x, qword_t& y)
{
#define BITON(x, b) ((x) & (0x01 << (b)))

    int carry;
    qword_t v;
    qword_t r = QWORD_STATIC_ZERO;

    r.b[0] = 0b11100001; // x128 + x7 + x2 + x + 1
    qwordCopy(y, v);
    qwordZero(y);

    for (int byte = 0; byte < 16; ++byte) {
        byte_t xi = x.b[byte];
        for (int bit = 7; bit >= 0; --bit) {
            if (BITON(xi, bit)) {
                qwordXor(v, y);
            }
            carry = BITON(v.b[15], 0);
            qwordShiftRight(v);
            if (carry) {
                qwordXor(r, v);
            }
        }
    }
}

void ghash(const qword_t& H, const byte_t* aad, unsigned int aadSize, const qword_t& Ssizes,
    const byte_t* dataOut, unsigned int dataSize, qword_t& Sout)
{
    qword_t Y = QWORD_STATIC_ZERO;
    qword_t tmp;

    // X1.. = aad
    for (unsigned int i = 0; i < aadSize; i += AES::BLOCKSIZE)
    {
        qwordCopy(aad + i, tmp);
        qwordXor(tmp, Y);
        gmul(H, Y);
    }

    // Xi.. = C
    for (unsigned int i = 0; i < dataSize; i += AES::BLOCKSIZE)
    {
        qwordCopy(dataOut + i, tmp);
        qwordXor(tmp, Y);
        gmul(H, Y);
    }

    // Xm = sizes
    qwordXor(Ssizes, Y);
    gmul(H, Y);

    qwordCopy(Y, Sout);
}

void inc32(qword_t& J)
{
    qwordInc(J, 4);
}

void gctr(const word_t* ksch, int Nr, const qword_t& icb,
    const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    // dataIn = X
    // dataOut = Y
    unsigned int i = 0;
    unsigned int offsetData = 0;
    unsigned int nBlocks = dataSize / 16;
    unsigned int lastBlock = dataSize % 16;
    unsigned int blockSize = AES::BLOCKSIZE;
    if (lastBlock != 0) {
        nBlocks++;
        if (nBlocks == 1) {
            blockSize = lastBlock;
        }
    }

    qword_t CB; // counter block
    qword_t cipherCB;
    qword_t plainBlock; // cipher block out
    qwordCopy(icb, CB);
    while (i < nBlocks)
    {
        qwordCopy(CB, cipherCB);
        cipherBlock(QWTOBUF(cipherCB), ksch, Nr);

        memcpy(QWTOBUF(plainBlock), dataIn + offsetData, blockSize);
        qwordXor(plainBlock, cipherCB);

        memcpy(dataOut + offsetData, QWTOBUF(cipherCB), blockSize);

        inc32(CB);
        ++i;
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetData += AES::BLOCKSIZE;
    }
}

/*****************************
 * GCM
 ****************************/
bool AES::gcm_crypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize, bool decrypt)
{
    const word_t* ksch = this->keySchedule.keys;

    // Read the tag
    qword_t TAG;
    byte_t* selectCryptBuffer;
    if (decrypt) {
        dataSize -= 16;
        memcpy(QWTOBUF(TAG), dataIn + dataSize, 16);
        selectCryptBuffer = (byte_t*)dataIn;
    }
    else {
        selectCryptBuffer = (byte_t*)dataOut;
    }

    // block H = qword_t de 0
    qword_t H = QWORD_STATIC_ZERO;
    cipherBlock(QWTOBUF(H), ksch, this->Nr);

    // block J = iv avec concat...
    qword_t J = QWORD_STATIC_ZERO;
    if (this->ivSize == 12) {
        memcpy(QWTOBUF(J), this->iv, this->ivSize);
        J.b[15] |= 0x01;
    }
    else {
        qword_t rightPart = QWORD_STATIC_ZERO;
        copyUIntToBuf(this->ivSize * 8, QWTOBUF(rightPart) + 12);
        ghash(H, nullptr, 0, rightPart, this->iv, getBlockRoundedSize(this->ivSize), J);
    }
    qword_t J0;
    qwordCopy(J, J0);

    // block C = GCTR(Key, inc32(J), Plain) = cipher ici
    inc32(J);
    gctr(ksch, this->Nr, J, dataIn, dataOut, dataSize);

    qword_t Sout = QWORD_STATIC_ZERO;
    qword_t Ssizes = QWORD_STATIC_ZERO;
    // 0^32 || aad size || 0^32 || cipher size, IN BITS !
    copyUIntToBuf(this->aadSize * 8, QWTOBUF(Ssizes) + 4);
    copyUIntToBuf(dataSize * 8, QWTOBUF(Ssizes) + 12);

    // Puts 0 at the end of cipher text for ghash
    if (dataSize % AES::BLOCKSIZE != 0)
    {
        int extraZeros = AES::BLOCKSIZE - (dataSize % AES::BLOCKSIZE);
        memset(selectCryptBuffer + dataSize, 0, extraZeros);
    }

    // block S = GHASH(H, block concat/padding)
    ghash(H, this->aad, this->getBlockRoundedSize(this->aadSize),
        Ssizes, selectCryptBuffer, getBlockRoundedSize(dataSize), Sout);

    // block size t = MSB(GCTR(Key, J, S)) = auth tag
    qword_t T = QWORD_STATIC_ZERO;
    gctr(ksch, this->Nr, J0, QWTOCBUF(Sout), QWTOBUF(T), AES::BLOCKSIZE);

    // return (C, T)
    TRACE_INFO("=> Authentification tag: ", bytesToHexString(QWTOCBUF(T), 16));
    if (decrypt) {
        if (memcmp(QWTOCBUF(TAG), QWTOCBUF(T), 16) != 0) {
            TRACE_ERROR("Bad authentification tag !");
            TRACE_ERROR("Tag expected : ", bytesToHexString(QWTOCBUF(TAG), 16));
            return false;
        }
    }
    else {
        memcpy(dataOut + dataSize, QWTOCBUF(T), 16); // Write tag at the end
    }

    return true;
}

bool AES::gcm_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    return gcm_crypt(dataIn, dataOut, dataSize, false);
}

bool AES::gcm_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    return gcm_crypt(dataIn, dataOut, dataSize, true);
}

} // namespace AES
