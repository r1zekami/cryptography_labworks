#pragma once
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "../alghoritms.h"

class RSA
{
    static constexpr uint16_t rsa_encryption_block_size{64};
public:
    static void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize=512);
    static std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    static std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);
    
    static void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename);
    
    static void WritePublicKey(const std::map<std::string, bi>& key, const std::string& keyFile);
    static void WritePrivateKey(const std::map<std::string, bi>& key, const std::string& keyFile);

    //digisig part
    static std::string GetName() { return "RSA"; }
    static std::string DigitalSigEncrypt(const std::string& HashedPlaintext, const std::string& PrivateKeyFile);
    static bool DigitalSigValidate(const std::string& EncryptedContent, const std::string& HashToCompare, const std::string& publicKeyFile);
    static boost::property_tree::ptree GetPublicKeyNode(std::string publicKeyFilePath)
    {
        boost::property_tree::ptree keyNode;
        auto publicKey = ReadKey(publicKeyFilePath);
        std::stringstream ss;
        ss << std::hex << publicKey["publicExponent"] << "0x" << publicKey["N"];
        std::string e = "0x" + ss.str().substr(0, ss.str().find("0x"));
        std::string n = "0x" + ss.str().substr(ss.str().find("0x") + 2);
    
        boost::property_tree::ptree KeyNode;
        KeyNode.put("e", e);
        KeyNode.put("n", n);
        return KeyNode;
    }

    static std::map<std::string, cpp_int> GetPublicKeyContainer(boost::property_tree::ptree propertyTree)
    {
        std::string PublicKeyStr_e = propertyTree.get<std::string>("public_key.e");
        std::string PublicKeyStr_n = propertyTree.get<std::string>("public_key.n");
        return {{"e", cpp_int(PublicKeyStr_e)}, {"n", cpp_int(PublicKeyStr_n)}};
    }
    
};

 