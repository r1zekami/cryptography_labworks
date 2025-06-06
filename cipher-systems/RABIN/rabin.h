#pragma once
#include "../../alghoritms.h"

class RABIN
{
private:
    static constexpr uint16_t rabin_encryption_block_size{64};
    static constexpr std::string rabin_encryption_tag{"RABINencrypted"};
    
    static cpp_int GenerateRabinPrime(uint64_t keySize);
    static std::string addTagsToPlaintext(const std::string& plaintext);
    static std::string RemoveRabinTags(const std::string& input);

public:
    static void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize=256);
    static std::vector<cpp_int> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    static std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);

    static void WriteEncryptedMessage(const std::vector<cpp_int>& ciphertext, const std::string& filename);

    static void WritePublicKey(const std::string& publicKeyFile, const cpp_int& n);
    static void WritePrivateKey(const std::string& privateKeyFile, const cpp_int& p, const cpp_int& q);
    
};