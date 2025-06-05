#pragma once

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <random>
#include "../cipher-systems/AES/AES.hpp"
#include "auth-client.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <functional>

using boost::property_tree::ptree;

class AuthServer {
public:
    AuthServer(std::string ID, Proto proto = Proto::TwoPassSymmetric)
        : ID(ID),
          proto(proto),
          acceptor_(io_service_, boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string("127.0.0.1"), 8888))
    {
    }

    void Run() {
        while (true) {
            std::cout << "[AuthServer] Start listening at " << ipAddr << ":" << connPort << "...\n";
            boost::asio::ip::tcp::socket socket(io_service_);
            acceptor_.accept(socket);
            HandleClientRequest(socket);
        }
    }

    void HandleClientRequest(boost::asio::ip::tcp::socket& socket)
    {
        if (proto == Proto::TwoPassSymmetric) {
            try {
                std::string Received = ReceiveMessage(socket);
                std::cout << "[AuthServer] Received: " << Received << std::endl;
                std::string M2 = Received.substr(0, Received.find(':'));
                std::string AESEncrypted = Received.substr(Received.find(':') + 1);
                auto AESEncryptedBytes = hexStringToBytes(AESEncrypted);
                auto AESDecryptedBytes = aes.DecryptCBC(AESEncryptedBytes, key, iv);
                std::string AESDecrypted = BytesToText(AESDecryptedBytes);
                std::cout << "[AuthServer] Client AES Decrypted: " << AESDecrypted << std::endl;
                std::string ClientNonce = AESDecrypted.substr(0, AESDecrypted.find(':'));

                std::cin.clear();
                std::string userInputM3;
                std::cout << "[AuthServer] Enter message (M3): ";
                std::cin >> userInputM3;
                
                std::string ResponseMessage = CreateResponseMessage(ClientNonce, userInputM3);
                std::cout << "[AuthServer] Response: " << ResponseMessage << std::endl;
                SendMessageToClient(socket, ResponseMessage);
                std::cout << "[AuthServer] Response sent" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "[AuthServer] Client handling error: " << e.what() << std::endl;
            }
        }
        else if (proto == Proto::ThreePassSymmetric) {
            std::string first_message = ReceiveMessage(socket);
            std::cout << "[AuthServer] Received first message: " << first_message << std::endl;
            std::vector<std::string> parts;
            boost::split(parts, first_message, boost::is_any_of(":"));
            if (parts.size() != 2) {
                std::cout << "[AuthServer] Invalid first message format\n";
                return;
            }
            std::string Ra = parts[0];
            std::string M1 = parts[1];

            std::string Rb = GenerateNonce();
            std::string M2 = "MESSAGE2";
            std::string M3 = "MESSAGE3";
            std::string to_encrypt = Ra + ":" + Rb + ":" + ID + ":" + M2;
            std::cout << "[AuthServer] " << M3 << ":" << to_encrypt << std::endl;
            auto to_encrypt_bytes = stringToBytes(to_encrypt);
            auto ciphertext_bytes = aes.EncryptCBC(to_encrypt_bytes, key, iv);
            std::string ciphertext = BytesToHexString(ciphertext_bytes);
            std::string second_message = M3 + ":" + ciphertext;
            std::cout << "[AuthServer] Sending second message: " << second_message << std::endl;
            SendMessageToClient(socket, second_message);

            std::string third_message = ReceiveMessage(socket);
            std::cout << "[AuthServer] Received third message: " << third_message << std::endl;
            size_t pos = third_message.find(':');
            if (pos == std::string::npos) {
                std::cout << "[AuthServer] Invalid third message format\n";
                SendMessageToClient(socket, "AUTH_FAILURE");
                return;
            }
            std::string M5 = third_message.substr(0, pos);
            std::string encrypted_third = third_message.substr(pos + 1);
            auto encrypted_bytes_third = hexStringToBytes(encrypted_third);
            auto decrypted_bytes_third = aes.DecryptCBC(encrypted_bytes_third, key, iv);
            std::string decrypted_third = BytesToText(decrypted_bytes_third);
            std::cout << "[AuthServer] Decrypted third message: " << decrypted_third << std::endl;
            std::vector<std::string> parts_third;
            boost::split(parts_third, decrypted_third, boost::is_any_of(":"));
            if (parts_third.size() != 4) {
                std::cout << "[AuthServer] Invalid decrypted third message format\n";
                SendMessageToClient(socket, "AUTH_FAILURE");
                return;
            }
            std::string Rb_prime = parts_third[0];
            std::string Ra_prime = parts_third[1];
            std::string A = parts_third[2];
            std::string M4 = parts_third[3];

            if (Rb_prime == Rb && Ra_prime == Ra) {
                std::cout << "[AuthServer] Authentication successful for client " << A << std::endl;
                SendMessageToClient(socket, "AUTH_SUCCESS");
            } else {
                std::cout << "[AuthServer] Authentication failed\n";
                SendMessageToClient(socket, "AUTH_FAILURE");
            }
        } else if (proto == Proto::Asymmetric)
        {
            std::string first_message = ReceiveMessage(socket);
            std::cout << "[AuthServer] Received first message: " << first_message << std::endl;
            std::vector<std::string> parts;
            boost::split(parts, first_message, boost::is_any_of(":"));

            std::string hashed = parts[0];
            std::string ClientID = parts[1];
            std::string Ciphertext = parts[2];

            std::vector<cpp_int> ciphertextArr;
            ciphertextArr.emplace_back(cpp_int(Ciphertext));
            
            RSA::WriteEncryptedMessage(ciphertextArr, encryptedTextPath);
            
            std::string Decrypted = RSA::Decrypt(encryptedTextPath, privateKeyPath);

            std::cout << "[AuthServer] Decrypted message: " << Decrypted << std::endl;

            parts.clear();
            boost::split(parts, Decrypted, boost::is_any_of(":"));
            std::string ClientNonceVerified = parts[0];
            std::string ClientIDverified = parts[1];

            if (SHA256::hashMessage(ClientNonceVerified) == hashed and
                ClientIDverified == ClientID)
            {
                SendMessageToClient(socket, ClientNonceVerified);
            } 
        }
        else if (proto == Proto::SingleUsePasswords) {
            std::string request = ReceiveMessage(socket);
            std::cout << "[AuthServer] Received request: " << request << std::endl;
            std::vector<std::string> parts;
            boost::split(parts, request, boost::is_any_of(":"));
            if (parts.size() < 2) {
                SendMessageToClient(socket, "INVALID_REQUEST");
                return;
            }

            std::string command = parts[0];
            std::string clientID = parts[1];

            if (command == "REGISTER") {
                if (parts.size() != 5) {
                    SendMessageToClient(socket, "INVALID_REQUEST");
                    return;
                }
                std::string hashFunctionName = parts[2];
                int N = std::stoi(parts[3]);
                std::string finalHash = parts[4];
                registerClient(clientID, hashFunctionName, N, finalHash);
                SendMessageToClient(socket, "REGISTRATION_SUCCESS");
            } else if (command == "AUTHENTICATE") {
                if (parts.size() != 4) {
                    SendMessageToClient(socket, "INVALID_REQUEST");
                    return;
                }
                int attempt = std::stoi(parts[2]);
                std::string oneTimePassword = parts[3];
                std::string result = authenticateClient(clientID, attempt, oneTimePassword);
                SendMessageToClient(socket, result);
            } else {
                SendMessageToClient(socket, "UNKNOWN_COMMAND");
            }
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

    void SendMessageToClient(boost::asio::ip::tcp::socket& socket, const std::string& message)
    {
        uint32_t length = htonl(message.size());
        boost::asio::write(socket, boost::asio::buffer(&length, sizeof(length)));
        boost::asio::write(socket, boost::asio::buffer(message));
    }

    std::string ReceiveMessage(boost::asio::ip::tcp::socket& socket)
    {
        uint32_t length = 0;
        size_t bytes_read = 0;
        while (bytes_read < sizeof(length)) {
            bytes_read += socket.read_some(boost::asio::buffer(reinterpret_cast<char*>(&length) + bytes_read, sizeof(length) - bytes_read));
        }
        length = ntohl(length);

        std::vector<char> data(length);
        bytes_read = 0;
        while (bytes_read < length) {
            bytes_read += socket.read_some(boost::asio::buffer(data.data() + bytes_read, length - bytes_read));
        }
        return std::string(data.begin(), data.end());
    }

    std::string CreateResponseMessage(std::string ClientNonce, std::string ServerData)
    {
        std::string Response;
        std::cout << "[AuthServer] Enter message (M4): ";
        std::cin >> Response;
        Response += ":";
        
        std::string ConcatedData = ClientNonce + ":" + ID + ":" + ServerData;
        std::cout << "[AuthServer] Response data: " << ConcatedData << std::endl;
        auto CiphertextBytes = aes.EncryptCBC(stringToBytes(ConcatedData), key, iv);
        std::string Ciphertext = BytesToHexString(CiphertextBytes);
        return Response + Ciphertext;
    }

private:
    std::function<std::string(std::string)> getHashFunction(const std::string& name) {
        if      (name == "STREEBOG256")  { return STREEBOG256::hashMessage; }
        else if (name == "STREEBOG512")  { return STREEBOG512::hashMessage; }
        else if (name == "SHA512")       { return SHA512::hashMessage; }
        else if (name == "SHA256")       { return SHA256::hashMessage; }
        else {return nullptr;}
    }

    void registerClient(const std::string& clientID, const std::string& hashFunctionName, int N, const std::string& finalHash) {
        auto hashFunc = getHashFunction(hashFunctionName);
        if (!hashFunc) {
            std::cout << "[AuthServer] Unknown hash function: " << hashFunctionName << std::endl;
            return;
        }

        ptree db;
        try {
            read_json(dbPath, db);
        } catch (const boost::property_tree::json_parser::json_parser_error& e) {
            db = ptree();
        }

        ptree clientData;
        clientData.put("hash_function", hashFunctionName);
        clientData.put("last_hash", finalHash);
        clientData.put("N", N);
        clientData.put("attempt", 0);

        db.put_child(clientID, clientData);
        write_json(dbPath, db);

        std::cout << "[AuthServer] Client " << clientID << " registered with final hash: " << finalHash << std::endl;
    }

    std::string authenticateClient(const std::string& clientID, int attempt, const std::string& oneTimePassword) {
        ptree db;
        try {
            read_json(dbPath, db);
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

        auto hashFunc = getHashFunction(hashFunctionName);
        if (!hashFunc) {
            return "AUTH_FAILURE: Unknown hash function";
        }

        std::string hashedPassword = hashFunc(oneTimePassword);
        if (hashedPassword == lastHash) {
            clientNode->put("last_hash", oneTimePassword);
            clientNode->put("attempt", currentAttempt + 1);
            db.put_child(clientID, *clientNode);
            write_json(dbPath, db);
            std::cout << "[AuthServer] Authentication successful for " << clientID << std::endl;
            return "AUTH_SUCCESS";
        } else {
            return "AUTH_FAILURE: Incorrect password";
        }
    }

    boost::asio::io_service io_service_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string ipAddr{"127.0.0.1"};
    std::string connPort{"8888"};
    std::string ID = "Bob";
    Proto proto;
    std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> iv = {0xce, 0xe4, 0xc4, 0x16, 0xc0, 0x10, 0x92, 0xa6, 0xb2, 0x9c, 0xa4, 0x50, 0x70, 0x0c, 0x5d, 0x86};
    AES aes{AESKeyLength::AES_128};

    std::string privateKeyPath = "auth/keys/private.key";
    std::string encryptedTextPath = "auth/temp/encrypted.txt";
    std::string dbPath = "auth/temp/passwords.json";
};