#pragma once
#include "../../alghoritms.h"

class FIAT_SHAMIR
{
    static constexpr uint16_t keySize{512};
    
public:

    static std::string GetName() { return "FIAT_SHAMIR"; }
    
    static void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t hashFuncOutputSize=256);
    static void WritePublicKey(const std::map<std::string, cpp_int>& key, const std::string& keyFile);
    static void WritePrivateKey(const std::map<std::string, cpp_int>& key, const std::string& keyFile);

    static std::string DigitalSigEncrypt(const std::string& Message, const std::string& PrivateKeyFile, std::function<std::string(std::string)> HashFunction);
    static bool DigitalSigValidate(const std::string& Message, const std::string& SignedContent, std::function<std::string(std::string)> HashFunction, const std::string& publicKeyFile);
    static boost::property_tree::ptree GetPublicKeyNode(std::string publicKeyFilePath);
    static std::map<std::string, cpp_int> GetPublicKeyContainer(boost::property_tree::ptree propertyTree);
    
};
