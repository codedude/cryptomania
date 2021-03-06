#include <iostream>
#include <string>
#include <vector>
#include <exception>

#include <boost/program_options.hpp>

#include <utility/logs.hpp>
#include <cliaes/loadData.hpp>
#include <cliaes/random_generator.hpp>
#include <libaes/libaes.hpp>
#include <libaes/types_helper.hpp>

struct Args
{
    std::string in;
    std::string out;
    std::string key;
    std::string iv;
    std::string aad;
    std::string tag;
    int generate;
    bool padding;
    bool verbose;
    bool printList;
    bool encrypt;
    AES::KEY_SIZE size;
    AES::MODE mode;
};

bool getArgs(int argc, char** argv, Args& args);
byte_t* hexStrToBytes(const std::string& str);

int main(int argc, char** argv)
{
    TRACE_START();

    // Get args from cmd line, as is
    Args args;
    if (!getArgs(argc, argv, args))
        return -1;

    if (!args.verbose) {
        TRACE_STOP();
    }

    if (args.generate > 0) {
        std::vector<std::uint8_t> vecBytes(args.generate);
        RNG::RandomGenerator rg;
        rg.randUInt8Vector(vecBytes.begin(), vecBytes.end());
        std::string hexString = bytesToHexString(vecBytes.data(), args.generate);
        std::cout << args.generate << " random bytes:" << std::endl
            << hexString << std::endl;
        return 0;
    }

    if (args.printList) {
        std::cout << AES::AES::getSupportedList() << std::endl;
        return 0;
    }

    unsigned int dataInSize = getFileSize(args.in);
    if (!args.padding && (args.mode == AES::MODE::ECB || args.mode == AES::MODE::CBC)
        && dataInSize % AES::AES::BLOCKSIZE != 0) {
        std::cout << "Padding is disabled, input data must be a multiple of 16 bytes " << std::endl;
        return -1;
    }

    // Get key and iv
    byte_t* key = nullptr;
    byte_t* iv = nullptr;
    byte_t* aad = nullptr;
    if ((key = hexStrToBytes(args.key)) == nullptr)
        return -1;
    if ((iv = hexStrToBytes(args.iv)) == nullptr)
        return -1;
    if (args.aad.size() != 0) {
        if ((aad = hexStrToBytes(args.aad)) == nullptr)
            return -1;
    }

    AES::AES aes;
    if (!aes.initialize(args.size, args.mode, args.padding, key))
    {
        std::cout << "Can't init aes " << std::endl;
        return -1;
    }
    if (!aes.setIv(iv, (int)args.iv.size() / 2)) {
        std::cout << "Can't set iv " << std::endl;
        return -1;
    }
    if (!aes.setAad(aad, (int)args.aad.size() / 2)) {
        std::cout << "Can't set aad " << std::endl;
        return -1;
    }

    delete[] aad;
    delete[] iv;
    delete[] key;

    TRACE_INFO(aes.getInfos());
    TRACE_INFO("Input file in: ", args.in);
    TRACE_INFO("Output file in: ", args.out);

    AES::PADDING pad = args.padding ? AES::PADDING::PKCS7 : AES::PADDING::NONE;
    byte_t* dataIn = nullptr;
    byte_t* dataOut = nullptr;
    unsigned int inBufSize;
    unsigned int outBufSize;

    if (args.encrypt) {
        inBufSize = AES::AES::getPlainInBufferSize(dataInSize, pad, args.mode);
    }
    else {
        inBufSize = AES::AES::getCipherInBufferSize(dataInSize, pad, args.mode);
    }

    // Read input file
    if ((dataIn = loadDataFromFile(args.in, inBufSize)) == nullptr)
    {
        std::cout << "Can't load file " << args.in << std::endl;
        return -1;
    }

    if (args.encrypt) {
        outBufSize = AES::AES::getCipherOutBufferSize(dataInSize, pad, args.mode);
    }
    else {
        outBufSize = AES::AES::getPlainOutBufferSize(dataInSize, pad, args.mode);
    }

    dataOut = new byte_t[outBufSize];
    if (args.encrypt) {
        aes.cipher(dataIn, dataOut, dataInSize);
    }
    else {
        aes.decipher(dataIn, dataOut, dataInSize);
        // Remove padding

        outBufSize -= AES::AES::getRevPaddingSize(dataOut, dataInSize, pad, args.mode);
    }

    if (!writeEncryptedDataToFile(args.out, dataOut, outBufSize))
    {
        std::cout << "Can't write file " << args.out << std::endl;
        return -1;
    }

    // Print error if asked for a specific tag check
    if (args.mode == AES::MODE::GCM && args.tag.size() > 0) {
        byte_t* tag = nullptr;
        if ((tag = hexStrToBytes(args.tag)) == nullptr)
            return -1;
        const byte_t* bufferToTest;
        if (args.encrypt)
            bufferToTest = dataOut + outBufSize - 16;
        else
            bufferToTest = dataIn + dataInSize - 16;
        if (memcmp(tag, bufferToTest, 16) != 0) {
            TRACE_ERROR("Expected tag: ", args.tag);
        }

        delete[] tag;
    }

    delete[] dataIn;
    delete[] dataOut;

    TRACE_STOP();

    return 0;
}

static bool checkArgs(boost::program_options::variables_map& vm, Args& args)
{
    if (vm.count("verbose")) {
        args.verbose = true;
    }
    else {
        args.verbose = false;
    }

    if (vm.count("help")) {
        return false;
    }

    if (vm.count("nopad")) {
        args.padding = false;
    }
    else {
        args.padding = true;
    }

    if (vm.count("list")) {
        args.printList = true;
        return true;
    }
    else {
        args.printList = false;
    }

    bool gotError = false;
    bool keySizeError = false;

    if (vm.count("generate")) {
        std::string n = vm["generate"].as<std::string>();
        try {
            args.generate = std::stoi(n);
        }
        catch (const std::exception& e) {
            (void)e;
            std::cout << "Invalid bytes number, must be in range [1;8092]" << std::endl;
            return false;
        }
        if (args.generate < 1 || args.generate > 8092) {
            std::cout << "Number of bytes generated must be in range [1;8092]" << std::endl;
            return false;
        }
        else {
            return true;
        }
    }
    else {
        args.generate = 0;
    }

    if (vm.count("mode"))
    {
        auto mode = vm["mode"].as<std::string>();
        if (mode == "ecb")
            args.mode = AES::MODE::ECB;
        else if (mode == "cbc")
            args.mode = AES::MODE::CBC;
        else if (mode == "ctr")
            args.mode = AES::MODE::CTR;
        else if (mode == "gcm")
            args.mode = AES::MODE::GCM;
        else {
            std::cout << "Mode is invalid" << std::endl;
            gotError = true;
        }
    }
    else {
        std::cout << "Mode is missing" << std::endl;
        gotError = true;
    }

    args.aad = ""; // Can be 0 size long
    args.tag = ""; // Only for gcm testing purpose
    if (args.mode == AES::MODE::GCM) {
        if (vm.count("aad"))
            args.aad = vm["aad"].as<std::string>();
        if (vm.count("tag")) {
            args.tag = vm["tag"].as<std::string>();
            if (args.tag.size() / 2 != AES::AES::BLOCKSIZE) {
                std::cout << "Authentification tag must be 16 bytes long" << std::endl;
                gotError = true;
            }
        }
    }

    if (vm.count("encrypt") && vm.count("decrypt")) {
        std::cout << "Both encrypt and decrypt are set, choose one !" << std::endl;
        gotError = true;
    }
    args.encrypt = vm.count("decrypt") == 0;

    if (vm.count("in")) {
        args.in = vm["in"].as<std::string>();
    }
    else {
        std::cout << "Input file is missing" << std::endl;
        gotError = true;
    }

    if (vm.count("out")) {
        args.out = vm["out"].as<std::string>();
    }
    else {
        if (args.encrypt)
            args.out = args.in + ".encrypted";
        else
            args.out = args.in + ".decrypted";
    }

    if (vm.count("size"))
    {
        auto size = vm["size"].as<std::string>();
        if (size == "128")
            args.size = AES::KEY_SIZE::S128;
        else if (size == "192")
            args.size = AES::KEY_SIZE::S192;
        else if (size == "256")
            args.size = AES::KEY_SIZE::S256;
        else {
            std::cout << "Key size is invalid" << std::endl;
            keySizeError = true;
            gotError = true;
        }
    }
    else {
        std::cout << "Key size is missing" << std::endl;
        keySizeError = true;
        gotError = true;
    }


    if (vm.count("key")) { // Need args.size first
        args.key = vm["key"].as<std::string>();
        int keyBitsLen = (int)args.key.size() * 4; // 1 char = 4 bits in hex
        int expectedSize = keySizeError ? 0 : (int)args.size;
        if (keyBitsLen != expectedSize) {
            std::cout << "Key should be " << expectedSize / 4 << " chars long " << std::endl;
            gotError = true;
        }
    }
    else {
        std::cout << "Key is missing" << std::endl;
        gotError = true;
    }

    if (vm.count("iv")) {
        args.iv = vm["iv"].as<std::string>();
        if (args.mode != AES::MODE::GCM && args.iv.size() != 32) {
            std::cout << "iv should be 32 chars long (16 bytes/128 bits)" << std::endl;
            gotError = true;
        }
        if (args.mode == AES::MODE::GCM) {
            if (!AES::AES::isGcmIvSizeValid((unsigned int)args.iv.size() / 2)) {
                std::cout << "Supported iv length in gcm (in bits): 1 <= i <= 2^64 -1 mod 8"
                    << std::endl;
                gotError = true;
            }
        }
    }
    else {
        std::cout << "iv is missing" << std::endl;
        gotError = true;
    }

    return !gotError;
}

bool getArgs(int argc, char** argv, Args& args)
{
    namespace po = boost::program_options;

    po::options_description desc("Command line options");
    desc.add_options()
        ("help,h", "produce help message then exit")
        ("key,k", po::value<std::string>(), "secret key in hexadecimal")
        ("iv,n", po::value<std::string>(), "iv/counter in hexadecimal")
        ("aad,a", po::value<std::string>(), "aad for gcm only in hexadecimal")
        ("list,l", "list supported algorithms then exit")
        ("encrypt,e", "encrypt input file (default)")
        ("decrypt,d", "decrypt input file")
        ("in,i", po::value<std::string>(), "input file")
        ("out,o", po::value<std::string>(), "output file (default = X.[de|en]crypted)")
        ("mode,m", po::value<std::string>(), "operation mode (ecb, cbc, ctr)")
        ("size,s", po::value<std::string>(), "key size (128, 192, 256)")
        ("generate,g", po::value<std::string>(), "generate X random bytes in hexadecimal then exit")
        ("nopad", "disable block padding (default is pkcs7). Input size must be a multiple of 16 bytes")
        ("verbose,v", "verbose mode (default = false)")
        ("tag,t", po::value<std::string>(), "authentification tag (for testing purpose only)");

    po::variables_map vm;
    try
    {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

    if (!checkArgs(vm, args))
    {
        std::cout << desc << std::endl;
        return false;
    }

    return true;
}

byte_t* hexStrToBytes(const std::string& str)
{
    byte_t* buffer = new byte_t[str.size() / 2];
    for (int i = 0; i < (int)str.size(); i += 2)
    {
        buffer[i / 2] = (byte_t)((std::stoi(std::string(1, str[i]), nullptr, 16) << 4)
            | (std::stoi(std::string(1, str[i + 1]), nullptr, 16)));
    }
    return buffer;
}
