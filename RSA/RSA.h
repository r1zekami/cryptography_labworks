#pragma once
#include "../alghoritms.h"

namespace RSA
{
    #define rsa_encryption_block_size 64

    void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize);
    std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);
    
    void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename);
    
    void WritePublicKey(const std::map<std::string, bi>& key, const std::string& keyFile);
    void WritePrivateKey(const std::map<std::string, bi>& key, const std::string& keyFile);
    
}

