#include <iostream>
#include <string>
#include <boost/program_options.hpp>

#include <utility/logs.hpp>
#include <cliaes/loadData.hpp>
#include <cliaes/random_generator.hpp>
#include <libaes/libaes.hpp>

struct Args
{
    std::string file;
    std::string str;
    std::string key;
    std::string iv;
    AES::KEY_SIZE type;
    AES::MODE mode;
};

bool getArgs(int argc, char** argv, Args& args);
byte_t* stringToBytes(const std::string& str);

int main(int argc, char** argv)
{
    TRACE_START();

    // Get args from cmd line, as is
    Args args;
    if (!getArgs(argc, argv, args))
        return 0;

    // Get key and iv
    byte_t* key = nullptr;
    byte_t* iv = nullptr;
    if ((key = stringToBytes(args.key)) == nullptr)
        return -1;
    if ((iv = stringToBytes(args.iv)) == nullptr)
        return -1;

    AES::AES aes;
    if (!aes.initialize(args.type, args.mode, key, iv))
    {
        std::cout << "Can't init aes " << std::endl;
        return -1;
    }

    TRACE_INFO(aes.getInfos());

    byte_t* data_plain = nullptr;
    unsigned int dataSizePlain = getFileSize(args.file);
    unsigned int dataSizeNeeded = aes.getFileSizeNeeded(dataSizePlain);
    unsigned int paddingSize = aes.getPaddingSize(dataSizePlain);
    if ((data_plain = loadDataFromFile(args.file, dataSizePlain + paddingSize)) == nullptr)
    {
        std::cout << "Can't load file " << args.file << std::endl;
        return -1;
    }

    byte_t* data_crypted = new byte_t[dataSizeNeeded];
    byte_t* data_decrypted = new byte_t[dataSizePlain + paddingSize];

    aes.cipher(data_plain, data_crypted, dataSizePlain);
    aes.decipher(data_crypted, data_decrypted, dataSizeNeeded);

    TRACE_INFO("Plaintext file in: ", args.file);
    std::string outputFileName = args.file + "_encrypted";
    if (!writeEncryptedDataToFile(outputFileName, data_crypted, dataSizeNeeded))
    {
        std::cout << "Can't write file " << outputFileName << std::endl;
        return -1;
    }
    TRACE_INFO("Encrypted file in: ", outputFileName);

    outputFileName = args.file + "_uncrypted";
    if (!writeEncryptedDataToFile(outputFileName, data_decrypted, dataSizePlain))
    {
        std::cout << "Can't write file " << outputFileName << std::endl;
        return -1;
    }
    TRACE_INFO("Decrypted file in: ", outputFileName);

    delete[] data_decrypted;
    delete[] data_crypted;
    delete[] data_plain;
    delete[] iv;
    delete[] key;

    TRACE_STOP();

    return 0;
}

static bool checkArgs(boost::program_options::variables_map& vm, Args& args)
{
    if (vm.count("help"))
    {
        return false;
    }

    if (vm.count("file"))
        args.file = vm["file"].as<std::string>();
    else
        return false;

    if (vm.count("key"))
    {
        auto key = vm["key"].as<std::string>();
        if (key.length() < 32)
        {
            std::cout << "Key error" << std::endl;
            return false;
        }
        args.key = key;
    }
    else
        return false;

    if (vm.count("iv"))
    {
        auto iv = vm["iv"].as<std::string>();
        if (iv.length() < 32)
        {
            std::cout << "iv error" << std::endl;
            return false;
        }
        args.iv = iv;
    }
    else
        return false;

    if (vm.count("type"))
    {
        auto type = vm["type"].as<std::string>();
        if (type == "128")
            args.type = AES::KEY_SIZE::S128;
        else if (type == "192")
            args.type = AES::KEY_SIZE::S192;
        else if (type == "256")
            args.type = AES::KEY_SIZE::S256;
        else
            return false;
    }
    else
        return false;

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
        else
            return false;
    }
    else
        return false;

    return true;
}

bool getArgs(int argc, char** argv, Args& args)
{
    namespace po = boost::program_options;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("file,fi", po::value<std::string>(), "file to encrypt")
        ("key,k", po::value<std::string>(), "secret key")
        ("iv,n", po::value<std::string>(), "IV or nonce")
        ("type,t", po::value<std::string>(), "type of aes (128, 192, 256)")
        ("mode,m", po::value<std::string>(), "operation mode (ebc, cbc, ctr)");

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

byte_t* stringToBytes(const std::string& str)
{
    byte_t* buffer = new byte_t[str.size() / 2];
    for (int i = 0; i < (int)str.size(); i += 2)
    {
        buffer[i / 2] = (byte_t)((std::stoi(std::string(1, str[i]), nullptr, 16) << 4)
            | (std::stoi(std::string(1, str[i + 1]), nullptr, 16)));
    }
    return buffer;
}
