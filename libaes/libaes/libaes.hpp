#ifndef LIBAES_LIBAES_HPP
#define LIBAES_LIBAES_HPP

#include <string>
#include <libaes/types.hpp>

namespace AES
{

enum class PADDING {
    NONE,
    ZEROS,
    PKCS5,
    PKCS7
};

enum class MODE {
    ECB,
    CBC,
    CTR,
    GCM
};

enum class KEY_SIZE {
    S128 = 128,
    S192 = 192,
    S256 = 256
};


/**
 * All size are expressed in bytes
 * All functions must be called AFTER initialization
 *
**/
class AES
{
public:
    static const int BLOCKSIZE = 16; // 16 bytes = 128 bits, AES specification

    AES()
    {
        this->verbose = false;
        this->hasInit = false;
        this->key = nullptr;
    }

    ~AES()
    {
        delete[] key;
        delete[] iv;
        delete[] aad;
    }

    // No need to be copied or moved
    AES(const AES& other) = delete;
    AES(const AES&& other) = delete;
    AES& operator=(const AES&& other) = delete;

    bool initialize(KEY_SIZE pKeySize, MODE pMode, bool pPadding, const byte_t* pKey);
    bool cipher(byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool decipher(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);

    bool setIv(const byte_t* pIv, int pIvSize);
    bool setAad(const byte_t* pAad, int pAadSize);

    void setVerbose(bool activate)
    {
        verbose = activate;
    }
    std::string getInfos();

    // Helpers to print infos or construct buffer
    static std::string getSupportedList();
    static int getKeySizeFromEnum(KEY_SIZE value);
    static std::string getModeFromEnum(MODE value);
    static std::string getPaddingFromEnum(PADDING value);
    static bool isGcmIvSizeValid(unsigned int pIvSize);
    static unsigned int getPaddingSize(unsigned int pDataSize, PADDING pPadding);
    static unsigned int getRevPaddingSize(const byte_t* pDataIn, unsigned int pDataSize,
        PADDING pPadding, MODE pMode);
    static unsigned int getBlockRoundedSize(unsigned int pDataSize);
    static unsigned int getPlainInBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode);
    static unsigned int getCipherOutBufferSize(unsigned int pDataSize, PADDING pPadding,
        MODE pMode);
    static unsigned int getCipherInBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode);
    static unsigned int getPlainOutBufferSize(unsigned int pDataSize, PADDING pPadding, MODE pMode);

private:
    struct KeySchedule
    {
        KeySchedule() : keys(nullptr), len(0) {}
        ~KeySchedule()
        {
            if (keys != nullptr)
            {
                delete[] keys;
                keys = nullptr;
                len = 0;
            }
        }
        word_t* keys;
        int len;
    };

    const int Nb = 4;   // 4 bytes = 32bits, AES specification
    int Nr;
    int Nk;

    KeySchedule keySchedule;

    bool verbose; // Activate trace
    bool hasInit; // Is state ready to cipher/decipher

    int keySize;
    unsigned int ivSize;
    unsigned int aadSize;
    PADDING padding;
    MODE mode;
    byte_t* key;
    byte_t* iv;
    byte_t* aad;

    void applyPadding(byte_t* data, unsigned int& dataSize);

    bool ecb_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool cbc_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool ctr_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool gcm_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool gcm_crypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize, bool decrypt);

    bool ecb_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool cbc_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool ctr_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool gcm_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
};

} // namespace AES

#endif
