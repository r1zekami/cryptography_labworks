#pragma once
#include "../alghoritms.h"


namespace ELGAMAL
{
    #define elgamal_encryption_block_size 32 //ЭТО БАЙТЫ НЕ БИТЫ, x8 
    
    bi findPrimitiveElement(const bi& p);
    void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize);

    std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile);
    std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile);
    
    void WritePublicKey(const std::string& publicKeyFile, const bi& p, const bi& alpha, const bi& beta);
    void WritePrivateKey(const std::string& privateKeyFile, const bi& p, const bi& a);
        
    void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename);

    
}