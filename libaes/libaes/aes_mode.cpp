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

// ghash with m = 2
// H = block
// X = 256 bit, m = 2 x block
// J = output block
void ghash2Blocks(const qword_t& H, const qword_t X[], qword_t& J)
{
    qword_t Y = QWORD_STATIC_ZERO;

    // i = 1
    qwordXor(X[0], Y);
    gmul(H, Y);

    // i = 2
    qwordXor(X[1], Y);
    gmul(H, Y);

    qwordCopy(Y, J);
}

void ghash(const qword_t& H, const qword_t& Saad, const qword_t& Ssizes,
    const byte_t* dataOut, unsigned int dataSize, qword_t& Sout)
{
    qword_t Y = QWORD_STATIC_ZERO;

    // X1 = aad
    qwordXor(Saad, Y);
    gmul(H, Y);

    // Xi = C
    for (unsigned int i = 0; i < dataSize; i += AES::BLOCKSIZE)
    {
        qword_t Scipher = QWORD_STATIC_ZERO;
        qwordCopy(dataOut + i, Scipher);

        qwordXor(Scipher, Y);
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
    for (unsigned int i = 0; i < nBlocks; ++i)
    {
        qwordCopy(CB, cipherCB);
        cipherBlock(QWTOBUF(cipherCB), ksch, Nr);

        memcpy(QWTOBUF(plainBlock), dataIn + offsetData, blockSize);
        qwordXor(plainBlock, cipherCB);

        memcpy(dataOut + offsetData, QWTOBUF(cipherCB), blockSize);

        inc32(CB);
        if (i == nBlocks - 1 && lastBlock != 0)
            blockSize = lastBlock;
        offsetData += AES::BLOCKSIZE;
    }
}

/*****************************
 * CTR
 ****************************/
bool AES::gcm_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;

    // block H = qword_t de 0
    qword_t H = QWORD_STATIC_ZERO;
    cipherBlock(QWTOBUF(H), ksch, this->Nr);

    // block J = iv avec concat...
    qword_t J = QWORD_STATIC_ZERO;
    memcpy(QWTOBUF(J), this->iv, this->ivSize);
    if (this->ivSize == 12) {
        J.b[15] |= 0x01;
    }
    else {
        // TODO a revoir ne marche pas
        qword_t ghashIn[2];
        word_t tmp = (word_t)this->ivSize;
        qwordCopy(this->iv, ghashIn[0]);
        memset(QWTOBUF(ghashIn[1]), 0, 16);
        memcpy(QWTOBUF(ghashIn[1]) + 12, &tmp, 4);
        ghash2Blocks(H, ghashIn, J);
    }
    qword_t J0;
    qwordCopy(J, J0);

    // block C = GCTR(Key, inc32(J), Plain) = cipher ici
    inc32(J);
    gctr(ksch, this->Nr, J, dataIn, dataOut, dataSize);

    // u = taille
    qword_t Sout = QWORD_STATIC_ZERO;
    qword_t Saad = QWORD_STATIC_ZERO;
    qword_t Ssizes = QWORD_STATIC_ZERO;

    // unsigned int u = dataSize % AES::BLOCKSIZE;
    // unsigned int v = this->aadSize % AES::BLOCKSIZE;

    // copy aad to the right, left filled with 0
    memcpy(QWTOBUF(Saad) + (AES::BLOCKSIZE - this->aadSize), this->aad, this->aadSize);

    // 0^32 || aad size || 0^32 || cipher size
    copyUIntToBuf(this->aadSize * 8, QWTOBUF(Ssizes) + 4);
    copyUIntToBuf(dataSize * 8, QWTOBUF(Ssizes) + 12);
    // block S = GHASH(H, block concat/padding)
    ghash(H, Saad, Ssizes, dataOut, dataSize + getPaddingSize(dataSize), Sout);
    // block size t = MSB(GCTR(Key, J, S)) = auth tag
    qword_t T = QWORD_STATIC_ZERO;
    gctr(ksch, this->Nr, J0, QWTOCBUF(Sout), QWTOBUF(T), AES::BLOCKSIZE);
    // return (C, T)
    std::cout << "Auth tag :" << bytesToHexString(QWTOCBUF(T), 16) << std::endl;

    return true;
}

bool AES::gcm_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    const word_t* ksch = this->keySchedule.keys;

    // block H = qword_t de 0
    qword_t H = QWORD_STATIC_ZERO;
    cipherBlock(QWTOBUF(H), ksch, this->Nr);

    // block J = iv avec concat...
    qword_t J = QWORD_STATIC_ZERO;
    memcpy(QWTOBUF(J), this->iv, this->ivSize);
    if (this->ivSize == 12) {
        J.b[15] |= 0x01;
    }
    else {
        // TODO a revoir ne marche pas
        qword_t ghashIn[2];
        word_t tmp = (word_t)this->ivSize;
        qwordCopy(this->iv, ghashIn[0]);
        memset(QWTOBUF(ghashIn[1]), 0, 16);
        memcpy(QWTOBUF(ghashIn[1]) + 12, &tmp, 4);
        ghash2Blocks(H, ghashIn, J);
    }
    qword_t J0;
    qwordCopy(J, J0);

    // block C = GCTR(Key, inc32(J), Plain) = cipher ici
    inc32(J);
    gctr(ksch, this->Nr, J, dataIn, dataOut, dataSize);

    // u = taille
    qword_t Sout = QWORD_STATIC_ZERO;
    qword_t Saad = QWORD_STATIC_ZERO;
    qword_t Ssizes = QWORD_STATIC_ZERO;

    // unsigned int u = dataSize % AES::BLOCKSIZE;
    // unsigned int v = this->aadSize % AES::BLOCKSIZE;

    // copy aad to the right, left filled with 0
    memcpy(QWTOBUF(Saad) + (AES::BLOCKSIZE - this->aadSize), this->aad, this->aadSize);

    // 0^32 || aad size || 0^32 || cipher size
    copyUIntToBuf(this->aadSize, QWTOBUF(Ssizes) + 4);
    copyUIntToBuf(dataSize, QWTOBUF(Ssizes) + 12);

    // block S = GHASH(H, block concat/padding)
    ghash(H, Saad, Ssizes, dataIn, dataSize + getPaddingSize(dataSize), Sout);
    // block size t = MSB(GCTR(Key, J, S)) = auth tag
    qword_t T = QWORD_STATIC_ZERO;
    gctr(ksch, this->Nr, J0, QWTOCBUF(Sout), QWTOBUF(T), AES::BLOCKSIZE);
    // return (C, T)
    std::cout << "Auth tag :" << bytesToHexString(QWTOCBUF(T), 16) << std::endl;

    return true;
}

} // namespace AES
