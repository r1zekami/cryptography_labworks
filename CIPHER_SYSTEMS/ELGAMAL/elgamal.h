#pragma once
#include "../../alghoritms.h"

class ELGAMAL
{
    static constexpr uint16_t elgamal_encryption_block_size{64}; //In bytes

public:
    static bi findPrimitive(const bi& p);
    
    static void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize=512);
    static std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    static std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);
    
    static void WritePublicKey(const std::map<std::string, bi>& keyContainer, const std::string& keyFile);
    static void WritePrivateKey(const std::map<std::string, bi>& keyContainer, const std::string& keyFile);
            
    static void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename);

    static std::string GetName() { return "ELGAMAL"; }
    static std::string DigitalSigEncrypt(const std::string& Message, const std::string& PrivateKeyFile, std::function<std::string(std::string)> HashFunction);
    static bool DigitalSigValidate(const std::string& Message, const std::string& SignedContent, std::function<std::string(std::string)> HashFunction, const std::string& publicKeyFile);

    static boost::property_tree::ptree GetPublicKeyNode(std::string publicKeyFilePath);

    static std::map<std::string, cpp_int> GetPublicKeyContainer(boost::property_tree::ptree propertyTree);
};