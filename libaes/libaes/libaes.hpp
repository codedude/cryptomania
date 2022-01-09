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
        this->iv = nullptr;
    }

    ~AES() = default;

    // No need to be copied or moved
    AES(const AES& other) = delete;
    AES(const AES&& other) = delete;
    AES& operator=(const AES&& other) = delete;

    bool initialize(KEY_SIZE pKeySize, MODE pMode, const byte_t* pKey, const byte_t* pIv);

    std::string getInfos();

    static std::string getSupportedList();
    static int getKeySizeFromEnum(KEY_SIZE value);
    static std::string getModeFromEnum(MODE value);

    unsigned int getPaddingSize(unsigned int dataSize);

    /*
    * Get the size needed by the encrypted buffer, since mode of operation add some value at the end
    * (i.e. IV, counter, AAD, AT...)
    * In addition to a padding, in ECB and CBC only
    */
    unsigned int getFileSizeNeeded(unsigned int dataSize);
    unsigned int getHeaderSize();
    unsigned int getRevPaddingSize(const byte_t* dataIn, unsigned int dataSize);

    bool cipher(byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool decipher(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);

    bool ecb_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool cbc_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool ctr_encrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);

    bool ecb_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool cbc_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);
    bool ctr_decrypt(const byte_t* dataIn, byte_t* dataOut, unsigned int dataSize);

    void setVerbose(bool activate)
    {
        verbose = activate;
    }

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
    PADDING padding;
    MODE mode;
    const byte_t* key;
    const byte_t* iv;

    /*
    * PKCS#7 padding
    */
    void applyPadding(byte_t* data, unsigned int& dataSize);
};

} // namespace AES

#endif
