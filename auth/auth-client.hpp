#pragma once

#include "../templates/asio-networking-template.h"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include "../cipher-systems/AES/AES.hpp"
#include "../cipher-systems/RSA/RSA.h"
#include "../hash-functions/hash-functions.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;

class Timestamp;
class Random;
enum class NonceType { Timestamp, RandomNumber };
enum class Proto {
                    TwoPassSymmetric,
                    ThreePassSymmetric,
                    Asymmetric,
                    SingleUsePasswords,
                    FiatShamir,
                    KeyExchange,
                };

class AuthClient : public asioLocalNetworkingTemplate {
public:
    AuthClient(std::string ID, Proto proto = Proto::TwoPassSymmetric, NonceType nonce_type = NonceType::RandomNumber)
        : ID(ID), Proto(proto), NonceType(nonce_type)
    {
    }

    void TwoPassSymmetricSequence();
    void ThreePassSymmetricSequence();
    void AsymmetricSequence();
    void SingleUsePasswordSequence();
    void FiatShamirSequence();
    void KeyExchangeSequence();

    void Run()
    {
        if (Proto == Proto::TwoPassSymmetric) {
            TwoPassSymmetricSequence();
        }
        if (Proto == Proto::ThreePassSymmetric) {
            ThreePassSymmetricSequence();
        }
        else if (Proto == Proto::Asymmetric) {
            AsymmetricSequence();
        }
        else if (Proto == Proto::SingleUsePasswords) {
            SingleUsePasswordSequence();
        }
        else if (Proto == Proto::FiatShamir) {
            FiatShamirSequence();
        }
        else if (Proto == Proto::KeyExchange) {
            KeyExchangeSequence();
        }
    }

    std::string GenerateNonce()
    {
        if (NonceType == NonceType::Timestamp) {
            boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
            std::string timestamp = boost::posix_time::to_iso_extended_string(now);
            std::cout << "[AuthClient] Timestamp nonce generated: " << timestamp << std::endl;
            return timestamp;
        } else {
            boost::random::mt19937 gen(std::random_device{}());
            boost::random::uniform_int_distribution<cpp_int> dist((fast_exp(2, 63) + 1), fast_exp(2, 64) - 1);
            std::stringstream ss;
            ss << std::hex << dist(gen);
            std::string randomNonce = "0x" + ss.str();
            std::cout << "[AuthClient] Random nonce generated: " << randomNonce << std::endl;
            return randomNonce;
        }
    }

    std::string CreateInitMessage(std::string Nonce)
    {
        std::string Message{""};
        Message = Nonce + ':' + ID + ':' + "ALICE_DATA";

        std::cout << "[AuthClient] Enter user data (M1): ";
        std::string userInputM1{""};
        std::cin >> userInputM1;
        Message = Nonce + ':' + ID + ':' + userInputM1;

        std::cout << "[AuthClient] Request data: " << Message << std::endl;
        auto CiphertextBytes = aes.EncryptCBC(stringToBytes(Message), Key, IV);
        std::string Ciphertext = BytesToHexString(CiphertextBytes);
        std::string userInputM2{""};

        std::cout << "[AuthClient] Enter message (M2): ";
        std::cin >> userInputM2;
        std::cout << "[AuthClient] Request: " << userInputM2 << ":" + Ciphertext << std::endl;

        return userInputM2 + ":" + Ciphertext;
    }

private:
    std::vector<std::string> GenerateHashChain(const std::string& password, int N) {
        std::vector<std::string> hashChain;
        std::string currentHash = password;
        hashChain.push_back(currentHash);
        for (int i = 0; i < N; ++i) {
            currentHash = HashFunction(currentHash);
            hashChain.push_back(currentHash);
        }
        return hashChain;
    }

    std::function<std::string(std::string)> HashFunction;
    std::string ChooseHashFunction() {
        std::cout << "[AuthClient] Choose hash function:\n1. STREEBOG256GOST\n2. STREEBOG512GOST\n3. SHA512\n4. SHA256\n";
        int choice;
        std::cin >> choice;
        switch (choice) {
            case 1: {HashFunction = STREEBOG256::hashMessage; return "STREEBOG256";}
            case 2: {HashFunction = STREEBOG512::hashMessage; return "STREEBOG512";}
            case 3: {HashFunction = SHA512::hashMessage; return "SHA512";}
            case 4: {HashFunction = SHA256::hashMessage; return "SHA256";}
            default: {HashFunction = SHA256::hashMessage; return "SHA256";}
        }
    }

    std::string GetPassword() {
        std::string pwd;
        std::cout << "[AuthClient] Enter password: ";
        std::cin >> pwd;
        return pwd;
    }

    size_t InternalCounter{0};
    std::string ID = "Alice";
    Proto Proto;
    NonceType NonceType;
    std::string PrimeNonce;
    std::vector<uint8_t> Key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> IV =  {0xce, 0xe4, 0xc4, 0x16, 0xc0, 0x10, 0x92, 0xa6, 0xb2, 0x9c, 0xa4, 0x50, 0x70, 0x0c, 0x5d, 0x86};
    AES aes{AESKeyLength::AES_128};
    std::vector<std::string> StoredHashChain;

    std::string PublicKeyPath = "auth/keys/public.key";
    std::string PrivateKeyPath = "auth/keys/private.key";
    std::string PlaintextPath = "auth/temp/plaintext.txt";
    std::string EncryptedTextPath = "auth/temp/encrypted.txt";

};