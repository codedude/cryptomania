#include <string>
#include <memory>

#include <libaes/types_helper.hpp>
#include <libaes/libaes.hpp>
#include <libaes/aes_cipher.hpp>

#include <utility/logs.hpp>

namespace AES
{

bool AES::initialize(KEY_SIZE pKeySize, MODE pMode, bool pPadding, const byte_t* pKey)
{
    if (pKey == nullptr)
        return false;

    this->mode = pMode;
    switch (pKeySize)
    {
    default:
    case KEY_SIZE::S128:
        this->keySize = 16;
        this->Nk = 4;
        this->Nr = 10;
        break;
    case KEY_SIZE::S192:
        this->keySize = 24;
        this->Nk = 6;
        this->Nr = 12;
        break;
    case KEY_SIZE::S256:
        this->keySize = 32;
        this->Nk = 8;
        this->Nr = 14;
        break;
    }

    if (!pPadding) {
        this->padding = PADDING::NONE;
    }
    else {
        this->padding = PADDING::PKCS7;
    }

    this->key = new byte_t[this->keySize];
    if (this->key == nullptr)
        return false;
    memcpy(this->key, pKey, this->keySize);


    this->keySchedule.len = this->Nb * (this->Nr + 1);
    this->keySchedule.keys = new word_t[this->keySchedule.len];
    if (this->keySchedule.keys == nullptr)
        return false;

    keyExpansion(this->key, this->keySchedule.keys, this->keySchedule.len, this->Nk);

    this->ivSize = 0;
    this->aadSize = 0;
    this->iv = nullptr;
    this->aad = nullptr;

    this->hasInit = true;

    return true;
}

/*
    Round block size to be 128 x m so we already have the full buffer for gcm
    Other mode will stay unchanged, and ivSize has the REAL size of the iv, not the full buffer
*/
bool AES::setIv(const byte_t* pIv, int pIvSize)
{
    if (!this->hasInit)
        return false;
    if (this->mode == MODE::GCM && !this->isGcmIvSizeValid(pIvSize))
        return false;

    this->iv = new byte_t[this->getBlockRoundedSize(pIvSize)];
    if (this->iv == nullptr)
        return false;
    this->ivSize = pIvSize;
    memcpy(this->iv, pIv, pIvSize);

    if (this->mode == MODE::GCM) {
        unsigned int roundedSize = this->getBlockRoundedSize(this->ivSize);
        if (roundedSize != this->ivSize)
            memset(this->iv + this->ivSize, 0, roundedSize - this->ivSize);
    }

    return true;
}

/*
    Round block size to be 128 x m so we already have the full buffer for gcm
*/
bool AES::setAad(const byte_t* pAad, int pAadSize)
{
    if (!this->hasInit)
        return false;

    if (this->mode == MODE::GCM) {
        if (pAad == nullptr || pAadSize == 0) { // Empty aad
            this->aadSize = 0;
            this->aad = nullptr;
        }
        else {
            this->aadSize = pAadSize;
            unsigned int roundedSize = this->getBlockRoundedSize(this->aadSize);
            this->aad = new byte_t[roundedSize];
            if (this->aad == nullptr)
                return false;
            memcpy(this->aad, pAad, this->aadSize);
            if (roundedSize != this->aadSize)
                memset(this->aad + this->aadSize, 0, roundedSize - this->aadSize);
        }
    }
    return true;
}

void AES::applyPadding(byte_t* data, unsigned int& dataSize)
{
    if (this->padding == PADDING::NONE)
        return;
    unsigned int paddingSize = AES::getPaddingSize(dataSize, this->padding);
    if (this->padding == PADDING::PKCS7) {
        memset(data + dataSize, paddingSize, paddingSize);
    }
    dataSize += paddingSize;
}

bool AES::cipher(byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    if (!hasInit)
        return false;
    if (dataIn == nullptr || dataOut == nullptr)
        return false;
    this->applyPadding((byte_t*)dataIn, dataSize);

    bool result;
    if (this->mode == MODE::ECB)
    {
        result = this->ecb_encrypt(dataIn, dataOut, dataSize);
    }
    else if (this->mode == MODE::CBC)
    {
        result = this->cbc_encrypt(dataIn, dataOut, dataSize);
    }
    else if (this->mode == MODE::CTR)
    {
        result = this->ctr_encrypt(dataIn, dataOut, dataSize);
    }
    else if (this->mode == MODE::GCM)
    {
        result = this->gcm_encrypt(dataIn, dataOut, dataSize);
    }
    else // Should never happen
    {
        result = false;
    }

    return result;
}

bool AES::decipher(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    if (!hasInit)
        return false;
    if (dataIn == nullptr || dataOut == nullptr)
        return false;

    bool result;
    if (this->mode == MODE::ECB)
    {
        result = this->ecb_decrypt(dataIn, dataOut, dataSize);
    }
    else if (this->mode == MODE::CBC)
    {
        result = this->cbc_decrypt(dataIn, dataOut, dataSize);
    }
    else if (this->mode == MODE::CTR)
    {
        result = this->ctr_decrypt(dataIn, dataOut, dataSize);
    }
    else if (this->mode == MODE::GCM)
    {
        result = this->gcm_decrypt(dataIn, dataOut, dataSize);
    }
    else // Should never happen
    {
        result = false;
    }

    return result;
}

bool AES::isGcmIvSizeValid(unsigned int pIvSize)
{
    // unsigned int GCM_IV_SIZE[] = { 128, 120, 112, 104, 96, 64, 32 };

    // pIvSize *= 8; // Given in bytes not bits
    // for (int i = 0; i < sizeof(GCM_IV_SIZE) / sizeof(unsigned int); ++i) {
    //     if (GCM_IV_SIZE[i] == pIvSize)
    //         return true;
    // }
    // return false;
    if (pIvSize > 0 && pIvSize < 256)
        return true;
    return false;
}
std::string AES::getSupportedList()
{
    std::string buffer;
    buffer += "Supported algorithms : ";
    buffer += "aes-[128|192|256]-[ecb|cbc|ctr|gcm]";
    buffer += "\nPadding = PKCS7";
    return buffer;
}

int AES::getKeySizeFromEnum(KEY_SIZE value)
{
    switch (value)
    {
    case KEY_SIZE::S128:
        return 128;
    case KEY_SIZE::S192:
        return 192;
    case KEY_SIZE::S256:
        return 256;
    }
    return -1;
}

std::string AES::getModeFromEnum(MODE value)
{
    switch (value)
    {
    case MODE::ECB:
        return "ECB";
    case MODE::CBC:
        return "CBC";
    case MODE::CTR:
        return "CTR";
    case MODE::GCM:
        return "GCM";
    }
    return "ERROR";
}

std::string AES::getPaddingFromEnum(PADDING value)
{
    switch (value)
    {
    case PADDING::PKCS7:
        return "PKCS7";
    case PADDING::NONE:
        return "None";
    }
    return "ERROR";
}

std::string AES::getInfos()
{
    if (!this->hasInit)
    {
        return "AES not initialized yet";
    }

    std::string buffer = "";
    buffer += "AES-" + std::to_string(this->keySize * 8) + "-"
        + AES::getModeFromEnum(this->mode);
    buffer += "\nKey: " + bytesToHexString(this->key, this->keySize);
    buffer += "\niv/counter (size = " + std::to_string(this->ivSize) + "): "
        + bytesToHexString(this->iv, this->ivSize);
    buffer += "\naad (size = " + std::to_string(this->aadSize) + "): "
        + bytesToHexString(this->aad, this->aadSize);
    buffer += "\nPadding: " + getPaddingFromEnum(this->padding);
    buffer += "\nGCM Tag: fixed length of 16 bytes";

    return buffer;
}

/*
    Only used on plain text
    All buffer must be a multiple of block size (16 bytes) for ease of implementation,
    since it does not add a lot of memory :)
    +1 block if padding is asked
*/
unsigned int AES::getPaddingSize(unsigned int pDataSize, PADDING pPadding)
{
    if (pPadding == PADDING::NONE || pDataSize == 0)
        return 0;
    if (pDataSize % AES::BLOCKSIZE == 0)
        return AES::BLOCKSIZE;
    return AES::BLOCKSIZE + (AES::BLOCKSIZE - pDataSize % AES::BLOCKSIZE);
}

// Only use on ciphered text
unsigned int AES::getRevPaddingSize(const byte_t* pDataIn, unsigned int pDataSize,
    PADDING pPadding, MODE pMode)
{
    if (pPadding == PADDING::NONE || pDataSize == 0)
        return 0;
    if (pMode == MODE::GCM)
        pDataSize -= 16; // Remove tag
    return pDataIn[pDataSize - 1];
}

unsigned int AES::getBlockRoundedSize(unsigned int pDataSize)
{
    if (pDataSize == 0)
        return 0;
    if (pDataSize % AES::BLOCKSIZE == 0)
        return pDataSize;
    return pDataSize + (AES::BLOCKSIZE - pDataSize % AES::BLOCKSIZE);
}

unsigned int AES::getPlainInBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode)
{
    (void)pMode;
    return pDataSize + getPaddingSize(pDataSize, pPadding);
}

// In gcm, cipher output must be a multiple of 16 bytes for last ghash step
// Else it must be equal to the Input, data + padding
unsigned int AES::getCipherOutBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode)
{
    unsigned int n = getPaddingSize(pDataSize, pPadding); // Padding link the input
    if (pMode == MODE::GCM)
    {
        pDataSize += AES::BLOCKSIZE; // Tag at the end
    }
    return pDataSize + n;
}

// Dont need more space, Tag space can be used to round Cipher txt in gcm
unsigned int AES::getCipherInBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode)
{
    (void)pPadding;
    (void)pMode;
    return pDataSize;
}

unsigned int AES::getPlainOutBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode)
{
    (void)pPadding; // Padding is removed AFTER the decryption
    if (pMode == MODE::GCM)
        pDataSize -= AES::BLOCKSIZE; // Remove Tag
    return pDataSize;
}

} // namespace AES
