#pragma once
#include "../alghoritms.h"

namespace RABIN
{
    #define rabin_encryption_block_size 64
    #define rabin_encryption_tag "RABINencrypted"
    
    bi generate_rabin_prime(int keySize);
    std::string addTagsToPlaintext(const std::string& plaintext);
    std::string RemoveRabinTags(const std::string& input);

    void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize);
    std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);
    
    void WritePublicKey(const std::string& publicKeyFile, const bi& n);
    void WritePrivateKey(const std::string& privateKeyFile, const bi& p, const bi& q);

    void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename);
    
}