#pragma once
#include "../alghoritms.h"
#include <boost/property_tree/ptree.hpp>

class ELGAMAL
{
    static constexpr uint16_t elgamal_encryption_block_size{64}; //ЭТО БАЙТЫ НЕ БИТЫ, x8 
    static bi findPrimitiveElement(const bi& p);

public:
    static void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize=512);
    static std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    static std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);
    
    static void WritePublicKey(const std::map<std::string, bi>& keyContainer, const std::string& keyFile);
    static void WritePrivateKey(const std::map<std::string, bi>& keyContainer, const std::string& keyFile);
            
    static void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename);

    //digisig part
    static std::string GetName() { return "ELGAMAL"; }
    static std::string DigitalSigEncrypt(const std::string& HashedPlaintext, const std::string& PrivateKeyFile);
    static bool DigitalSigValidate(const std::string& EncryptedContent, std::string HashToCompare, const std::string& publicKeyFile);
    static boost::property_tree::ptree GetPublicKeyNode(std::string publicKeyFilePath)
    {
        boost::property_tree::ptree keyNode;
        auto publicKey = ReadKey(publicKeyFilePath);
        boost::property_tree::ptree KeyNode;
        KeyNode.put("p", "0x" + to_hex(publicKey["p"]));
        KeyNode.put("alpha", "0x" + to_hex(publicKey["alpha"]));
        KeyNode.put("beta", "0x" + to_hex(publicKey["beta"]));
        return KeyNode;
        return KeyNode;
    }

    static std::map<std::string, cpp_int> GetPublicKeyContainer(boost::property_tree::ptree propertyTree)
    {
        std::string p_str = propertyTree.get<std::string>("public_key.p");
        std::string alpha_str = propertyTree.get<std::string>("public_key.alpha");
        std::string beta_str = propertyTree.get<std::string>("public_key.beta");
        return {{"p", cpp_int(p_str)},{"alpha", cpp_int(alpha_str)},{"beta", cpp_int(beta_str)}};
    }
    
private:
    static std::string to_hex(const bi& num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }
};