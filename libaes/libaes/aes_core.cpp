#include <string>
#include <memory>

#include <libaes/types_helper.hpp>
#include <libaes/libaes.hpp>
#include <libaes/aes_cipher.hpp>

namespace AES
{

bool AES::initialize(KEY_SIZE pKeySize, MODE pMode, const byte_t* pKey, const byte_t* pIv)
{
    if (pKey == nullptr)
        return false;

    this->key = pKey;
    this->iv = pIv;
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

    switch (this->mode)
    {
    case MODE::ECB:
    case MODE::CBC:
        this->padding = PADDING::PKCS7;
        break;

    default:
        this->padding = PADDING::NONE;
        break;
    }

    this->keySchedule.len = this->Nb * (this->Nr + 1);
    this->keySchedule.keys = new word_t[this->keySchedule.len];
    if (this->keySchedule.keys == nullptr)
    {
        return false;
    }

    keyExpansion(this->key, this->keySchedule.keys, this->keySchedule.len, this->Nk);

    this->hasInit = true;

    return true;
}

void AES::applyPadding(byte_t* data, unsigned int& dataSize)
{
    unsigned int paddingSize = AES::getPaddingSize(dataSize);
    memset(data + dataSize, paddingSize, paddingSize);
    dataSize += paddingSize;
}

bool AES::cipher(byte_t* dataIn, byte_t* dataOut, unsigned int dataSize)
{
    if (!hasInit)
        return false;

    if (dataIn == nullptr || dataOut == nullptr || dataSize == 0)
        return false;

    if (this->padding != PADDING::NONE)
    {
        this->applyPadding((byte_t*)dataIn, dataSize);
    }

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

    if (dataIn == nullptr || dataOut == nullptr || dataSize == 0)
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
    else // Should never happen
    {
        result = false;
    }

    return result;
}

std::string AES::getSupportedList()
{
    std::string buffer;
    buffer += "Supported algorithm : ";
    buffer += "aes-[128|192|256]-[ecb|cbc|ctr]";
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

std::string AES::getInfos()
{
    if (!this->hasInit)
    {
        return "AES not initialized yet";
    }

    std::string buffer = "";
    buffer += "AES-";
    buffer += std::to_string(this->keySize * 8);
    buffer += "-";
    buffer += AES::getModeFromEnum(this->mode);
    buffer += " / Key: ";
    buffer += bytesToHexString(this->key, this->keySize);
    buffer += " / iv: ";
    buffer += bytesToHexString(this->iv, this->keySize);

    return buffer;
}

unsigned int AES::getPaddingSize(unsigned int dataSize)
{
    if (!this->hasInit || this->padding == PADDING::NONE)
        return 0;

    if (dataSize % AES::BLOCKSIZE == 0)
        return AES::BLOCKSIZE;
    return AES::BLOCKSIZE - (dataSize % AES::BLOCKSIZE) + AES::BLOCKSIZE;
}

unsigned int AES::getHeaderSize()
{
    unsigned int n = 0;
    switch (this->mode)
    {
    case MODE::ECB:
        n = 0;
        break;
    case MODE::CBC:
        n = 16;
        break;
    case MODE::CTR:
        n = 16;
        break;
    case MODE::GCM:
        n = 32;
        break;
    default:
        break;
    }
    return n;
}

unsigned int AES::getFileSizeNeeded(unsigned int dataSize)
{
    if (!this->hasInit)
    {
        return 0;
    }

    unsigned int n = this->getHeaderSize();
    unsigned int paddingSize = 0;
    if (this->padding != PADDING::NONE)
        paddingSize = this->getPaddingSize(dataSize);

    return dataSize + paddingSize + n;
}

} // namespace AES
