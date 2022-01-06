#ifndef LIBAES_LIBAES_HPP
#define LIBAES_LIBAES_HPP

#include <string>
#include <libaes/types.hpp>

namespace AES
{


enum class MODE
{
    ECB,
    CBC,
    CTR,
    GCM
};

enum class KEY_SIZE
{
    AES128,
    AES192,
    AES256
};

struct KeySchedule
{
    KeySchedule() : keys(nullptr), len(0) {}
    ~KeySchedule()
    {
        if (keys != nullptr)
            delete[] keys;
    }
    word_t* keys;
    int len;
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

    AES() : keySchedule(), key(nullptr), padding(false), verbose(false), hasInit(false)
    {
    }

    ~AES() = default;

    // No need to be copied or moved
    AES(const AES& other) = delete;
    AES(const AES&& other) = delete;
    AES& operator=(const AES&& other) = delete;

    bool initialize(MODE pOperationMode, const byte_t* pKey, KEY_SIZE pKeySize);

    std::string getInfos();
    static int getKeySizeFromEnum(KEY_SIZE value);
    static std::string getModeFromEnum(MODE value);
    dword_t getPaddingSize(dword_t size);

    /*
    * Get the size needed by the encrypted buffer, since mode of operation add some value at the end
    * (i.e. IV, counter, AAD, AT...)
    * In addition to a padding, in ECB and CBC only
    */
    dword_t getFileSizeNeeded(dword_t dataSize);

    bool cipher(byte_t* dataIn, byte_t* dataOut, dword_t dataSize);
    bool cipher(byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize);
    bool decipher(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize);

    bool ecb_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize);
    bool cbc_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize);
    bool ctr_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize);
    bool gcm_encrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, const byte_t* iv, int ivSize);

    bool ecb_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize);
    bool cbc_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize);
    bool ctr_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize);
    bool gcm_decrypt(const byte_t* dataIn, byte_t* dataOut, dword_t dataSize, dword_t ivSize);

    void setVerbose(bool activate)
    {
        verbose = activate;
    }

private:
    const int Nb = 4;                         // 4 bytes = 32bits, AES specification
    const int defaultIvSize = AES::BLOCKSIZE; // Use only for CBC/CTR when no iv is provided
    int keySize;
    int Nr;
    int Nk;
    MODE operationMode;

    KeySchedule keySchedule;
    const byte_t* key;

    bool padding;
    bool verbose; // Activate trace
    bool hasInit; // Is state ready to cipher/decipher

    dword_t getHeaderSize();
    /*
    * PKCS#7 padding
    */
    void applyPadding(byte_t* data, dword_t& dataSize);
};

} // namespace AES

#endif
