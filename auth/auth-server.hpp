#pragma once

#include "../templates/asio-networking-template.h"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include "../cipher-systems/AES/AES.hpp"
#include "../cipher-systems/RSA/RSA.h"
#include "auth-client.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <functional>

using boost::property_tree::ptree;

class AuthServer : public asioLocalNetworkingTemplate {
public:
    AuthServer(std::string ID, Proto proto = Proto::TwoPassSymmetric)
        : ID(ID), Proto(proto)
    {
    }

    void Run() {
        while (true) {
            std::cout << "[AuthServer] Start listening at 127.0.0.1:8888...\n";
            HandleClientRequest();
        }
    }

    void TwoPassSymmetricSequence();
    void ThreePassSymmetricSequence();
    void AsymmetricSequence();
    void SingleUsePasswordSequence();
    void FiatShamirSequence();
    void KeyExchangeSequence();
    
    void HandleClientRequest()
    {
        if (Proto == Proto::TwoPassSymmetric) {
            TwoPassSymmetricSequence();
        }
        else if (Proto == Proto::ThreePassSymmetric) {
            ThreePassSymmetricSequence();
        }
        else if (Proto == Proto::Asymmetric) {
            AsymmetricSequence();
        }
        else if (Proto == Proto::SingleUsePasswords) {
            SingleUsePasswordSequence();
        }
        else if (Proto == Proto::FiatShamir)
        {
            FiatShamirSequence();
        } else if (Proto == Proto::KeyExchange)
        {
            KeyExchangeSequence();
        }
    }

    std::string GenerateNonce()
    {
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<cpp_int> dist((fast_exp(2, 63) + 1), fast_exp(2, 64) - 1);
        std::stringstream ss;
        ss << std::hex << dist(gen);
        std::string randomNonce = "0x" + ss.str();
        std::cout << "[AuthServer] Random nonce generated: " << randomNonce << std::endl;
        return randomNonce;
    }

    std::string CreateResponseMessage(std::string ClientNonce, std::string ServerData)
    {
        std::string Response;
        std::cout << "[AuthServer] Enter message (M4): ";
        std::cin >> Response;
        Response += ":";

        std::string ConcatedData = ClientNonce + ":" + ID + ":" + ServerData;
        std::cout << "[AuthServer] Response data: " << ConcatedData << std::endl;
        auto CiphertextBytes = aes.EncryptCBC(stringToBytes(ConcatedData), Key, IV);
        std::string Ciphertext = BytesToHexString(CiphertextBytes);
        return Response + Ciphertext;
    }

private:
    std::function<std::string(std::string)> GetHashFunction(const std::string& Name) {
        if (Name == "STREEBOG256") { return STREEBOG256::hashMessage; }
        else if (Name == "STREEBOG512") { return STREEBOG512::hashMessage; }
        else if (Name == "SHA512") { return SHA512::hashMessage; }
        else if (Name == "SHA256") { return SHA256::hashMessage; }
        else { return nullptr; }
    }

    void RegisterClient(const std::string& clientID, const std::string& hashFunctionName, int N, const std::string& finalHash) {
        auto HashFunc = GetHashFunction(hashFunctionName);
        if (!HashFunc) {
            std::cout << "[AuthServer] Unknown hash function: " << hashFunctionName << std::endl;
            return;
        }

        ptree db;
        try {
            read_json(DB_Path, db);
        } catch (const boost::property_tree::json_parser::json_parser_error& e) {
            db = ptree();
        }

        ptree clientData;
        clientData.put("hash_function", hashFunctionName);
        clientData.put("last_hash", finalHash);
        clientData.put("N", N);
        clientData.put("attempt", 0);

        db.put_child(clientID, clientData);
        write_json(DB_Path, db);

        std::cout << "[AuthServer] Client " << clientID << " registered with final hash: " << finalHash << std::endl;
    }

    std::string AuthenticateClient(const std::string& clientID, int attempt, const std::string& oneTimePassword) {
        ptree db;
        try {
            read_json(DB_Path, db);
        } catch (const boost::property_tree::json_parser::json_parser_error& e) {
            return "AUTH_FAILURE: Database not found";
        }

        auto clientNode = db.get_child_optional(clientID);
        if (!clientNode) {
            return "AUTH_FAILURE: Client not found";
        }

        std::string hashFunctionName = clientNode->get<std::string>("hash_function");
        std::string lastHash = clientNode->get<std::string>("last_hash");
        int N = clientNode->get<int>("N");
        int currentAttempt = clientNode->get<int>("attempt");

        if (currentAttempt >= N) {
            return "AUTH_FAILURE: No attempts remaining";
        }
        if (currentAttempt != attempt) {
            return "AUTH_FAILURE: Wrong attempt number";
        }

        auto hashFunc = GetHashFunction(hashFunctionName);
        if (!hashFunc) {
            return "AUTH_FAILURE: Unknown hash function";
        }

        std::string hashedPassword = hashFunc(oneTimePassword);
        if (hashedPassword == lastHash) {
            clientNode->put("last_hash", oneTimePassword);
            clientNode->put("attempt", currentAttempt + 1);
            db.put_child(clientID, *clientNode);
            write_json(DB_Path, db);
            std::cout << "[AuthServer] Authentication successful for " << clientID << std::endl;
            return "AUTH_SUCCESS";
        } else {
            return "AUTH_FAILURE: Incorrect password";
        }
    }

    std::string CreateTimestamp();

    std::string ID = "Bob";
    Proto Proto;
    std::vector<uint8_t> Key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> IV = {0xce, 0xe4, 0xc4, 0x16, 0xc0, 0x10, 0x92, 0xa6, 0xb2, 0x9c, 0xa4, 0x50, 0x70, 0x0c, 0x5d, 0x86};
    AES aes{AESKeyLength::AES_128};

    std::string PublicKeyPath = "auth/keys/public.key";
    std::string PrivateKeyPath = "auth/keys/private.key";
    std::string PlaintextPath = "auth/temp/plaintext.txt";
    std::string EncryptedTextPath = "auth/temp/encrypted.txt";
    std::string DB_Path = "auth/temp/passwords.json";
    

};
