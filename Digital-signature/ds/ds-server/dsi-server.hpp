#pragma once
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <iostream>
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/time_facet.hpp>

#include "../../../hash-functions/hash-functions.h"
#include "../../../CIPHER_SYSTEMS/RSA/RSA.h"
#include "../../../CIPHER_SYSTEMS/ELGAMAL/elgamal.h"
#include "../../../CIPHER_SYSTEMS/FIAT_SHAMIR/fiat-shamir.h"

class DSServer {
public:
    DSServer(std::string ipAddress, std::string connectionPort)
    :
    acceptor_(io_service_, boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address::from_string(ipAddress),
        stoi(connectionPort))),
    ipAddr(ipAddress),
    connPort(connectionPort)
    {
        //Run();
    }
    
    void Run() {
        while (true) {
            std::cout << "[Server] Start listening at " << ipAddr << ":" << connPort << "...\n";
            boost::asio::ip::tcp::socket socket(io_service_);
            acceptor_.accept(socket);
            HandleClientRequest(socket);
        }
    }
    
private:
    void HandleClientRequest(boost::asio::ip::tcp::socket& socket) {
        try {
            char Data[131072];
            boost::system::error_code ec;
            size_t Length = socket.read_some(boost::asio::buffer(Data), ec);
            if (ec) {
                std::cerr << "Error reading: " << ec.message() << std::endl;
                return;
            }
            Data[Length] = '\0';
            std::string Received(Data, Length);

            std::cout << "[Server] Successfully received data from Client\n";
            boost::property_tree::ptree pt;
            std::stringstream ss(Received);
            boost::property_tree::read_json(ss, pt);
            
            std::string EncryptionMethodName = pt.get<std::string>("SignerInfos.SignatureAlgorithmIdentifier");
            std::string HashFunctionName = pt.get<std::string>("DigestAlgorithmIdentifiers");
            std::string EncryptedMessage = pt.get<std::string>("SignerInfos.SignatureValue");
            ClientMessagePlaintext = pt.get<std::string>("EncapsulatedContentInfo.OCTET_STRING_OPTIONAL");
            std::string HashedClientPlaintext{};
            std::string SignerIdentifier = pt.get<std::string>("SignerInfos.SignerIdentifier");
            std::map<std::string, cpp_int> ClientPublicKeyContainer;

            std::cout << "[Server] Client is using " + EncryptionMethodName + " and " + HashFunctionName + "\n";
            SetupEncryptionMethod(EncryptionMethodName);
            SetHashFunction(HashFunctionName);
            HashedClientPlaintext = HashFunction(ClientMessagePlaintext);
            std::cout << "[Server] Plaintext message: " << ClientMessagePlaintext << "\n";
            std::cout << "[Server] Hashed message: " << HashedClientPlaintext << "\n";

            ClientPublicKeyContainer = CipherMethodClass::GetPublicKeyContainer(pt.get_child("SignerInfos.SubjectPublicKeyInfo"));
            CipherMethodClass::WritePublicKey(ClientPublicKeyContainer, clientPublicKeyPath);
            std::cout << "[Server] Client public key written to:\n - " + clientPublicKeyPath + "\n\n";

            std::cout << "[Server] Checking if client-signed hash is valid...\n";
            bool isSignatureValid = CipherMethodClass::DigitalSigValidate(
                ClientMessagePlaintext,
                EncryptedMessage,
                HashFunction,
                clientPublicKeyPath
            );
            if (!isSignatureValid)
            {
                std::cout << "[Server] [ERR] Sign is incorrect. Aborting... \n";
                socket.close();
                return;
            }
            
            std::cout << "[Server] Validation successful!\n";
            CipherMethodClass::GenerateKeys(publicKeyPath, privateKeyPath, 512);

            boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
            std::string timestamp = boost::posix_time::to_iso_extended_string(now);
            std::cout << "[Server] Timestamp generated: " << timestamp << std::endl;

            std::string ClientPlaintext = ClientMessagePlaintext;
            std::string ClientSignature = EncryptedMessage;

            std::string MessageForServerSignature = ClientPlaintext + ClientSignature + timestamp;
            std::string ServerSignature = CipherMethodClass::DigitalSigEncrypt(MessageForServerSignature, privateKeyPath, HashFunction);

            boost::property_tree::ptree Root;
            Root.put("CMSVersion", "1");
            Root.put("DigestAlgorithmIdentifiers", HashFunctionName);
            Root.add_child("EncapsulatedContentInfo", pt.get_child("EncapsulatedContentInfo"));

            boost::property_tree::ptree SignerInfos = pt.get_child("SignerInfos");

            boost::property_tree::ptree UnsignedAttributes;
            try {
                UnsignedAttributes = SignerInfos.get_child("UnsignedAttributes");
            } catch (const boost::property_tree::ptree_bad_path&) {
                UnsignedAttributes = boost::property_tree::ptree();
            }

            UnsignedAttributes.put("ObjectIdentifier", "signature-time-stamp");

            boost::property_tree::ptree SetOfAttributeValue;
            try {
                SetOfAttributeValue = UnsignedAttributes.get_child("SET_OF_AttributeValue");
            } catch (const boost::property_tree::ptree_bad_path&) {
                SetOfAttributeValue = boost::property_tree::ptree();
            }

            SetOfAttributeValue.put("Timestamp", timestamp);
            SetOfAttributeValue.put("ServerSignature", ServerSignature);
            SetOfAttributeValue.add_child("ServerPublicKeyInfo", CipherMethodClass::GetPublicKeyNode(publicKeyPath));

            UnsignedAttributes.put_child("SET_OF_AttributeValue", SetOfAttributeValue);
            SignerInfos.put_child("UnsignedAttributes", UnsignedAttributes);

            Root.add_child("SignerInfos", SignerInfos);
            boost::property_tree::write_json(jsonAnswerPath, Root, std::locale(), true);
            std::cout << "[Server] Json answer formed at:\n - " + jsonAnswerPath << "\n\n";

            std::ifstream jsonAnswerFile = std::ifstream(jsonAnswerPath);
            std::string content((std::istreambuf_iterator<char>(jsonAnswerFile)), std::istreambuf_iterator<char>());
            jsonAnswerFile.close();
            
            boost::asio::write(socket, boost::asio::buffer(content), ec);
            if (ec) {
                std::cerr << "Error writing response: " << ec.message() << std::endl;
                socket.close(ec);
                return;
            }
            socket.close();
            
        } catch (const std::exception& e) {
            std::cerr << "[Server] Client handling error: " << e.what() << std::endl;
        }
    }

    void GenerateJsonAnswer()
    {
        
    }

    
    void SendResponse(boost::asio::ip::tcp::socket& socket) {
        try {
            std::string response = "[Server] Request processed successfully!";
            boost::system::error_code errorCode;
            boost::asio::write(socket, boost::asio::buffer(response), errorCode);
            if (errorCode) {
                std::cerr << "[Server] Error writing response: " << errorCode.message() << std::endl;
                socket.close(errorCode);
                return;
            }

            socket.close(errorCode);
            if (errorCode) {
                std::cerr << "[Server] Error closing socket: " << errorCode.message() << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[Server] Error sending response: " << e.what() << std::endl;
            boost::system::error_code ec;
            socket.close(ec);
        }
    }

    
    void SetupEncryptionMethod(std::string EncryptionMethodName)
    {
        if (EncryptionMethodName == "RSA") {
            CipherMethodClass::GenerateKeys =          RSA::GenerateKeys;
            CipherMethodClass::DigitalSigEncrypt =     RSA::DigitalSigEncrypt;
            CipherMethodClass::DigitalSigValidate =    RSA::DigitalSigValidate;
            CipherMethodClass::WritePublicKey =        RSA::WritePublicKey;
            CipherMethodClass::GetPublicKeyContainer = RSA::GetPublicKeyContainer;
            CipherMethodClass::GetPublicKeyNode =      RSA::GetPublicKeyNode;
        }
        else if (EncryptionMethodName == "ELGAMAL")  {
            CipherMethodClass::GenerateKeys =          ELGAMAL::GenerateKeys;
            CipherMethodClass::DigitalSigEncrypt =     ELGAMAL::DigitalSigEncrypt;
            CipherMethodClass::DigitalSigValidate =    ELGAMAL::DigitalSigValidate;
            CipherMethodClass::WritePublicKey =        ELGAMAL::WritePublicKey;
            CipherMethodClass::GetPublicKeyContainer = ELGAMAL::GetPublicKeyContainer;
            CipherMethodClass::GetPublicKeyNode =      ELGAMAL::GetPublicKeyNode;
        }
        else if (EncryptionMethodName == "FIAT_SHAMIR")  {
            CipherMethodClass::GenerateKeys =          FIAT_SHAMIR::GenerateKeys;
            CipherMethodClass::DigitalSigEncrypt =     FIAT_SHAMIR::DigitalSigEncrypt;
            CipherMethodClass::DigitalSigValidate =    FIAT_SHAMIR::DigitalSigValidate;
            CipherMethodClass::WritePublicKey =        FIAT_SHAMIR::WritePublicKey;
            CipherMethodClass::GetPublicKeyContainer = FIAT_SHAMIR::GetPublicKeyContainer;
            CipherMethodClass::GetPublicKeyNode =      FIAT_SHAMIR::GetPublicKeyNode;
        }
        else
        {
            std::cout << "Invalid encryption method: " << EncryptionMethodName << " - Set encryption method RSA\n";
        }
    }

    
    void SetHashFunction(std::string hashFunctionName)
    {
        if      (hashFunctionName == "STREEBOG256")      { HashFunction = STREEBOG256CHEF::hashMessage; }   
        else if (hashFunctionName == "STREEBOG512")      { HashFunction = STREEBOG512CHEF::hashMessage; }
        else if (hashFunctionName == "STREEBOG256-GOST") { HashFunction = STREEBOG256::hashMessage;     }
        else if (hashFunctionName == "STREEBOG512-GOST") { HashFunction = STREEBOG512::hashMessage;     }
        else if (hashFunctionName == "SHA512")           { HashFunction = SHA512::hashMessage;          } 
        else if (hashFunctionName == "SHA256")           { HashFunction = SHA256::hashMessage;          }
        else
        {
            std::cout << "Invalid hash function: " << hashFunctionName << " - Set hash function SHA256\n";
            HashFunction = SHA256::hashMessage;
        }
    }

    
private:
     boost::asio::io_service io_service_;
     boost::asio::ip::tcp::acceptor acceptor_;

     const std::string clientPublicKeyPath = "digital-signature/ds-server/keys/client-public.key";
     const std::string publicKeyPath =       "digital-signature/ds-server/keys/public.key";
     const std::string privateKeyPath =      "digital-signature/ds-server/keys/private.key";
     const std::string jsonAnswerPath =      "digital-signature/ds-server/answer.json";
     
     std::string ClientMessagePlaintext;
     std::string ipAddr{"127.0.0.1"};
     std::string connPort{"8888"};
     std::string generatedTimestamp{""};
     
     std::function<std::string(std::string)> HashFunction;
     
     //Encryption Method function signatures
     class CipherMethodClass {
     public:
         inline static std::function<void(const std::string&, const std::string&, uint64_t)> GenerateKeys;
         inline static std::function<std::string(const std::string&, const std::string&, std::function<std::string(std::string)>)> DigitalSigEncrypt;
         inline static std::function<bool(const std::string&, const std::string&, std::function<std::string(std::string)>, const std::string&)> DigitalSigValidate;
         inline static std::function<std::map<std::string, cpp_int>(boost::property_tree::ptree)> GetPublicKeyContainer;
         inline static std::function<void(const std::map<std::string, cpp_int>&, const std::string&)> WritePublicKey;
         inline static std::function<boost::property_tree::ptree(std::string)> GetPublicKeyNode;
     };
    
};