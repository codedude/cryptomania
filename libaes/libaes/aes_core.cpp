#include <string>
#include <memory>

#include <libaes/types_helper.hpp>
#include <libaes/libaes.hpp>
#include <libaes/aes_cipher.hpp>

namespace AES
{

bool AES::initialize(MODE pOperationMode, const byte_t* pKey, KEY_SIZE pKeySize)
{
    if (pKey == nullptr)
        return false;

    this->key = pKey;
    this->operationMode = pOperationMode;

    switch (pKeySize)
    {
    default:
    case KEY_SIZE::AES128:
        this->keySize = 16;
        this->Nk = 4;
        this->Nr = 10;
        break;
    case KEY_SIZE::AES192:
        this->keySize = 24;
        this->Nk = 6;
        this->Nr = 12;
        break;
    case KEY_SIZE::AES256:
        this->keySize = 32;
        this->Nk = 8;
        this->Nr = 14;
        break;
    }

    switch (this->operationMode)
    {
    case MODE::ECB:
    case MODE::CBC:
        this->padding = true;
        break;

    default:
        this->padding = false;
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

void AES::applyPadding(byte_t* data, dword_t& dataSize)
{
    byte_t paddingSize = (byte_t)AES::getPaddingSize(dataSize);
    memset(data + dataSize, (int)paddingSize, (size_t)paddingSize);
    dataSize += (dword_t)paddingSize;
}

bool AES::cipher(byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize)
{
    if (!hasInit)
        return false;

    if (dataIn == nullptr || dataOut == nullptr || iv == nullptr)
        return false;
    if (dataSize == 0 || ivSize < 1)
        return false;

    if (this->padding)
    {
        this->applyPadding((byte_t*)dataIn, dataSize);
    }

    bool result;
    if (this->operationMode == MODE::ECB)
    {
        result = this->ecb_encrypt(dataIn, dataOut, dataSize);
    }
    else if (this->operationMode == MODE::CBC)
    {
        result = this->cbc_encrypt(dataIn, dataOut, dataSize, iv, ivSize);
    }
    else if (this->operationMode == MODE::CTR)
    {
        result = this->ctr_encrypt(dataIn, dataOut, dataSize, iv, ivSize);
    }
    else if (this->operationMode == MODE::GCM) // Not yet implemented
    {
        result = this->gcm_encrypt(dataIn, dataOut, dataSize, iv, ivSize);
    }
    else // Should never happen
    {
        result = false;
    }

    return result;
}

bool AES::cipher(byte_t* dataIn, byte_t* dataOut, dword_t dataSize)
{
    int tmp_ivSize = this->defaultIvSize;
    byte_t* tmp_iv = new byte_t[tmp_ivSize];
    if (tmp_iv == nullptr)
        return false;

    // TODO : random here
    //RNG::ByteGenerator rngGen(0);
    //rngGen.genBytes(tmp_iv, tmp_ivSize);

    bool result = this->cipher(dataIn, dataOut, dataSize, tmp_iv, tmp_ivSize);

    delete[] tmp_iv;
    return result;
}

bool AES::decipher(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize)
{
    if (!hasInit)
        return false;

    if (dataIn == nullptr || dataOut == nullptr)
        return false;
    if (dataSize == 0)
        return false;

    bool result;
    if (this->operationMode == MODE::ECB)
    {
        result = this->ecb_decrypt(dataIn, dataOut, dataSize);
    }
    else if (this->operationMode == MODE::CBC)
    {
        result = this->cbc_decrypt(dataIn, dataOut, dataSize, ivSize);
    }
    else if (this->operationMode == MODE::CTR)
    {
        result = this->ctr_decrypt(dataIn, dataOut, dataSize, ivSize);
    }
    else if (this->operationMode == MODE::GCM) // Not yet implemented
    {
        result = this->gcm_decrypt(dataIn, dataOut, dataSize, ivSize);
    }
    else // Should never happen
    {
        result = false;
    }

    return result;
}

int AES::getKeySizeFromEnum(KEY_SIZE value)
{
    switch (value)
    {
    case KEY_SIZE::AES128:
        return 128;
    case KEY_SIZE::AES192:
        return 192;
    case KEY_SIZE::AES256:
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
    buffer += AES::getModeFromEnum(this->operationMode);
    buffer += " / Key: ";
    buffer += bytesToHexString(this->key, this->keySize);

    return buffer;
}

dword_t AES::getPaddingSize(dword_t size)
{
    if (!this->hasInit || !this->padding)
        return 0;

    if (size % AES::BLOCKSIZE == 0)
        return AES::BLOCKSIZE;
    return AES::BLOCKSIZE - (size % AES::BLOCKSIZE) + AES::BLOCKSIZE;
}

dword_t AES::getHeaderSize()
{
    dword_t n = 0;
    switch (this->operationMode)
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

dword_t AES::getFileSizeNeeded(dword_t dataSize)
{
    if (!this->hasInit)
    {
        return 0;
    }

    dword_t n = this->getHeaderSize();
    dword_t paddingSize = 0;
    if (this->padding)
        paddingSize = this->getPaddingSize(dataSize);

    return dataSize + paddingSize + n;
}

} // namespace AES
