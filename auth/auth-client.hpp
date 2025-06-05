#pragma once

#include <boost/asio.hpp>
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
enum class Proto { TwoPassSymmetric, ThreePassSymmetric, Asymmetric, SingleUsePasswords };

class AuthClient {
public:
    AuthClient(std::string ID, Proto proto = Proto::TwoPassSymmetric, NonceType nonce_type = NonceType::RandomNumber) :
        ID(ID),
        proto(proto),
        nonce_type(nonce_type),
        io_context(),
        socket(io_context)
    {
    }

    void Run()
    {
        if (proto == Proto::TwoPassSymmetric) {
            boost::asio::ip::tcp::resolver resolver(io_context);
            boost::system::error_code ec;
            boost::asio::connect(socket, resolver.resolve("127.0.0.1", "8888"), ec);
            if (ec) {
                std::cout << "[AuthClient] Connection failed: " << ec.message() << std::endl;
                return;
            }

            std::string Nonce = GenerateNonce();
            primeNonce = Nonce;
            std::string InitMessage = CreateInitMessage(Nonce);
            std::cout << "[AuthClient] Sending request to server...\n";
            SendMessageToServer(socket, InitMessage);
            std::cout << "[AuthClient] Successfully sent request to server.\n";
            std::string ServerResponse = ReceiveMessage(socket);
            std::cout << "[AuthClient] Server response: " << ServerResponse << "\n";
            std::string ResponseEncryptedPart = ServerResponse.substr(ServerResponse.find(':') + 1);
            auto AESDecryptedBytes = aes.DecryptCBC(hexStringToBytes(ResponseEncryptedPart), key, iv);
            std::string AESDecrypted = BytesToText(AESDecryptedBytes);
            std::cout << "[AuthClient] Decrypted response: " << AESDecrypted << std::endl;

            std::string DecryptedNonce = AESDecrypted.substr(0, AESDecrypted.find(':'));
            std::cout << "[AuthClient] Decrypted nonce: " << DecryptedNonce << std::endl;

            if (primeNonce == DecryptedNonce)
            {
                std::cout << "[AuthClient] Auth verified\n";
            } else
            {
                std::cout << "[AuthClient] Wrong nonce, auth denied\n";
            }
            
            socket.close();
            std::cin.get();
            return;
        }
        if (proto == Proto::ThreePassSymmetric) {
            boost::asio::ip::tcp::resolver resolver(io_context);
            boost::system::error_code ec;
            boost::asio::connect(socket, resolver.resolve("127.0.0.1", "8888"), ec);
            if (ec) {
                std::cout << "[AuthClient] Connection failed: " << ec.message() << std::endl;
                return;
            }

            std::string Ra = GenerateNonce();
            std::string M1 = "MESSAGE1";
            std::string first_message = Ra + ":" + M1;
            std::cout << "[AuthClient] Sending first message: " << first_message << std::endl;

            SendMessageToServer(socket, first_message);

            std::string second_message = ReceiveMessage(socket);
            std::cout << "[AuthClient] Received second message: " << second_message << std::endl;
            size_t pos = second_message.find(':');
            if (pos == std::string::npos) {
                std::cout << "[AuthClient] Invalid second message format\n";
                socket.close();
                return;
            }
            std::string M3 = second_message.substr(0, pos);
            std::string encrypted = second_message.substr(pos + 1);
            auto encrypted_bytes = hexStringToBytes(encrypted);
            auto decrypted_bytes = aes.DecryptCBC(encrypted_bytes, key, iv);
            std::string decrypted = BytesToText(decrypted_bytes);
            std::cout << "[AuthClient] Decrypted second message: " << decrypted << std::endl;
            std::vector<std::string> parts;
            boost::split(parts, decrypted, boost::is_any_of(":"));
            if (parts.size() != 4) {
                std::cout << "[AuthClient] Invalid decrypted message format\n";
                socket.close();
                return;
            }
            std::string Ra_prime = parts[0];
            std::string Rb = parts[1];
            std::string B = parts[2];
            std::string M2 = parts[3];
            if (Ra_prime != Ra) {
                std::cout << "[AuthClient] Authentication failed: Nonce (Ra) mismatch\n";
                socket.close();
                return;
            }
            std::cout << "[AuthClient] Verified server response. Rb: " << Rb << ", B: " << B << ", M2: " << M2 << std::endl;

            std::string M4 = "MESSAGE4";
            std::string M5 = "MESSAGE5";
            std::string to_encrypt = Rb + ":" + Ra + ":" + ID + ":" + M4;
            std::cout << "[AuthClient] Third message data: " << M5 << ":" << to_encrypt << std::endl;
            auto to_encrypt_bytes = stringToBytes(to_encrypt);
            auto ciphertext_bytes = aes.EncryptCBC(to_encrypt_bytes, key, iv);
            std::string ciphertext = BytesToHexString(ciphertext_bytes);
            std::string third_message = M5 + ":" + ciphertext;
            std::cout << "[AuthClient] Sending third message: " << third_message << std::endl;
            SendMessageToServer(socket, third_message);

            std::string final_response = ReceiveMessage(socket);
            std::cout << "[AuthClient] Server final response: " << final_response << std::endl;
            socket.close();
            std::cin.get();
        }
        else if (proto == Proto::Asymmetric)
        {
            while (true)
            {
                boost::asio::ip::tcp::resolver resolver(io_context);
                boost::system::error_code ec;
                boost::asio::connect(socket, resolver.resolve("127.0.0.1", "8888"), ec);
                if (ec) {
                    std::cout << "[AuthClient] Connection failed: " << ec.message() << "\n[AuthClient] Want to try again? (y/n): ";
                    uint8_t UserInput;
                    std::cin >> UserInput;
                    if (UserInput == 'n' or UserInput == 'N') {
                        return;
                    } else if (UserInput == 'y' or UserInput == 'Y') {
                        continue;
                    }
                } else {break;}
            }
            std::cin.get();
            
            primeNonce = GenerateNonce();
            
            RSA::GenerateKeys(publicKeyPath, privateKeyPath, 512);

            std::string messageToEncrypt = primeNonce + ":" + ID;

            std::ofstream file(plaintextPath);
            file << messageToEncrypt;
            file.close();
            
            std::vector<cpp_int> encryptedMessage = RSA::Encrypt(plaintextPath, publicKeyPath);

            std::string rawEncrypted;
            std::stringstream ss;
            for (int i = 0; i < encryptedMessage.size(); i++)
            {
                ss << "0x" << std::hex << encryptedMessage[i];
            }
            rawEncrypted = ss.str();
            std::string message = SHA256::hashMessage(primeNonce);
            message += ":" + ID + ":" + rawEncrypted;

            std::cout << "[AuthClient] Sending message: " << message << std::endl;
            SendMessageToServer(socket, message);

            std::string answer = ReceiveMessage(socket);

            std::cout << "[AuthClient] Received message: " << answer << std::endl;

            if (answer == primeNonce)
            {
                std::cout << "[AuthClient] AUTH SUCCESS." << std::endl;
            } else
            {
                std::cout << "[AuthClient] AUTH FAILED." << std::endl;
            }
             
            std::cin.get();
        }
        else if (proto == Proto::SingleUsePasswords) {
            boost::asio::ip::tcp::resolver resolver(io_context);
            boost::system::error_code ec;

            while (true) {
                std::cout << "[AuthClient] Choose action:\n1. Register\n2. Authenticate\n3. Exit\n";
                int choice;
                std::cin >> choice;
                if (choice == 1) {
                    boost::asio::connect(socket, resolver.resolve("127.0.0.1", "8888"), ec);
                    if (ec) {
                        std::cout << "[AuthClient] Connection failed: " << ec.message() << std::endl;
                        return;
                    }
                    std::string hashFunctionName = chooseHashFunction();
                    std::string password = getPassword();
                    std::cout << "[AuthClient] Enter number of passwords (N): ";
                    int N;
                    std::cin >> N;
                    std::vector<std::string> hashChain = generateHashChain(password, N);
                    std::string finalHash = hashChain.back();
                    std::string request = "REGISTER:" + ID + ":" + hashFunctionName + ":" + std::to_string(N) + ":" + finalHash;
                    std::cout << "[AuthClient] Sending registration request: " << request << std::endl;
                    SendMessageToServer(socket, request);
                    std::string response = ReceiveMessage(socket);
                    std::cout << "[AuthClient] Server response: " << response << std::endl;
                    if (response == "REGISTRATION_SUCCESS") {
                        storedHashChain = hashChain;
                        internalCounter = 0;
                        }
                    socket.close();
                } else if (choice == 2) {
                    boost::asio::connect(socket, resolver.resolve("127.0.0.1", "8888"), ec);
                    if (ec) {
                        std::cout << "[AuthClient] Connection failed: " << ec.message() << std::endl;
                        return;
                    }
                    
                    std::string oneTimePassword = "EMPTY";
                    if (!storedHashChain.empty() && internalCounter < storedHashChain.size() - 1) {
                        oneTimePassword = storedHashChain[storedHashChain.size() - 2 - internalCounter];
                    }

                    std::string request = "AUTHENTICATE:" + ID + ":" + std::to_string(internalCounter) + ":" + oneTimePassword;
                    SendMessageToServer(socket, request);
                    std::string response = ReceiveMessage(socket);
                    std::cout << "[AuthClient] Server response: " << response << std::endl;
                    if (response == "AUTH_SUCCESS") {
                        internalCounter++;
                    }
                    socket.close();
                } else if (choice == 3) {
                    break;
                } else {
                    std::cout << "[AuthClient] Invalid choice\n";
                }
            }
        }
    }

    std::string GenerateNonce()
    {
        if (nonce_type == NonceType::Timestamp) {
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

    void SendMessageToServer(boost::asio::ip::tcp::socket& socket, const std::string& message)
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

    std::string CreateInitMessage(std::string Nonce)
    {
        std::string Message{""};

        Message = Nonce + ':' + ID + ':' + "ALICE_DATA";

        std::cout << "[AuthClient] Enter user data (M1): ";
        std::string userInputM1{""};
        std::cin >> userInputM1;
        Message = Nonce + ':' + ID + ':' +  userInputM1;
        
        std::cout << "[AuthClient] Request data: " << Message << std::endl;
        auto CiphertextBytes = aes.EncryptCBC(stringToBytes(Message), key, iv);
        std::string Ciphertext = BytesToHexString(CiphertextBytes);
        std::string userInputM2{""};

        std::cout << "[AuthClient] Enter message (M2): ";
        std::cin >> userInputM2;
        std::cout << "[AuthClient] Request: " << userInputM2 << ":" + Ciphertext << std::endl;
        
        return userInputM2 + ":" + Ciphertext;
    }

private:
    std::vector<std::string> generateHashChain(const std::string& password, int N) {
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
    std::string chooseHashFunction() {
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

    std::string getPassword() {
        std::string pwd;
        std::cout << "[AuthClient] Enter password: ";
        std::cin >> pwd;
        return pwd;
    }

    size_t internalCounter{0};
    std::string ID = "Alice";
    Proto proto;
    NonceType nonce_type;
    std::string primeNonce;
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket;
    std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> iv = {0xce, 0xe4, 0xc4, 0x16, 0xc0, 0x10, 0x92, 0xa6, 0xb2, 0x9c, 0xa4, 0x50, 0x70, 0x0c, 0x5d, 0x86};
    AES aes{AESKeyLength::AES_128};
    std::vector<std::string> storedHashChain;
    
    std::string publicKeyPath = "auth/keys/public.key";
    std::string privateKeyPath = "auth/keys/private.key";
    std::string plaintextPath = "auth/temp/plaintext.txt";
};