#pragma once
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <typeinfo>

// #include "../../Hash-functions/hash-functions.h"
// #include "../../RSA/RSA.h"

using boost::asio::ip::tcp;

template<typename CipherMethodClass, typename HashFunctionClass>
class Client {
    public:

    Client( std::string ipAddress,
            std::string connectionPort,
            std::string Message)
    :
        HashFunction(HashFunctionClass::hashMessage),
        ipAddr(ipAddress),
        connPort(connectionPort),
        Message(Message),
        io_context(),
        socket(io_context)
    {
        //Run();
    }

    
    void Run()
    {
        std::cout << "[Client] Client created with:\n"
            << " - Cipher Method: " << CipherMethodClass::GetName() << "\n"
            << " - Hash function: " << HashFunctionClass::GetName() << "\n\n";

        CipherMethodClass::GenerateKeys(publicKeyPath, privateKeyPath);
        std::cout << "[Client] Client keys are generated, look for them at:"
            "\n - " << publicKeyPath <<
            "\n - " << privateKeyPath << "\n\n";
        
        std::cout << "[Client] Generating json request for server...\n";
        GenerateJsonRequest();
        std::cout << "[Client] Initial JSON request is generated at:"
            "\n - " << jsonRequestPath << "\n\n";
        
        std::cout << "[Client] Sending request to server...\n";
        while (true) {
            if (SendRequestToServer()) {
                break;
            }
            std::cout << "\n[Client] Error while trying to connect. Wanna try again? (y/n): ";
            char response;
            std::cin >> response;
            if (response == 'n' || response == 'N') {
                std::cout << "[Client] Exit...\n";
                break;
            }
        }
        std::cout << "[Client] Successfully sent request to server.\n";

        GetServerResponse();
        std::cout << "[Client] Response from server written to:\n - " + responseJsonFilePath + "\n\n";

        if (ValidateResponse(responseJsonFilePath))
            { std::cout << "[Client] Signature data is CORRECT [+]\n"; }
        else
            { std::cout << "[Client] Signature data is INCORRECT [-]\n"; }

        //socket.shutdown(tcp::socket::shutdown_both, ec);
        socket.close();
        std::cout << "[Client] Waiting for input to exit...";
        std::cin.get();
    }
    
private:
    void GenerateJsonRequest()
    {
        boost::property_tree::ptree root;

        root.put("message", Message);
        root.put("encryption_method", CipherMethodClass::GetName());
        root.put("hash_function", HashFunctionClass::GetName());
        root.put("encrypted_message", CipherMethodClass::DigitalSigEncrypt(HashFunction(this->Message), privateKeyPath));
        root.add_child("public_key", CipherMethodClass::GetPublicKeyNode(publicKeyPath));
    
        boost::property_tree::write_json(jsonRequestPath, root, std::locale(), true);
        return;
        //it should work fine without branching tbh
        if (CipherMethodClass::GetName() == "RSA")
        {
            boost::property_tree::ptree root;

            root.put("message", Message);
            root.put("encryption_method", CipherMethodClass::GetName());
            root.put("hash_function", HashFunctionClass::GetName());
            root.put("encrypted_message", CipherMethodClass::DigitalSigEncrypt(HashFunction(this->Message), privateKeyPath));
            root.add_child("public_key", CipherMethodClass::GetPublicKeyNode(publicKeyPath));
    
            boost::property_tree::write_json(jsonRequestPath, root, std::locale(), true);
        }
        else
        {
            std::cout << "[Client] Cannot create JSON request cause there is no "
                         "implementation of JSON request for any other cipher method rather than RSA" << '\n';
        }
    }

    
    bool ValidateResponse(std::string ResponseJsonFilePath)
    {
        boost::property_tree::ptree pt;
        std::ifstream file(ResponseJsonFilePath);
        if (!file.is_open()) {
            std::cout << "[Client] Cannot open response file: " << ResponseJsonFilePath << '\n';
            return false;
        }
        boost::property_tree::read_json(file, pt);
        file.close();


        std::map<std::string, cpp_int> ServerPublicKeyContainer;

        ServerPublicKeyContainer = CipherMethodClass::GetPublicKeyContainer(pt);
        
        CipherMethodClass::WritePublicKey(ServerPublicKeyContainer, serverPublicKeyPath);
        
        std::string message_a = pt.get<std::string>("message_a");
        std::string signature_a = pt.get<std::string>("signature_a");
        std::string message_b = pt.get<std::string>("message_b");
        std::string signature_b = pt.get<std::string>("signature_b");

        // std::cout << message_a << '\n';
        // std::cout << HashFunction(message_a) << '\n';
        // std::cout << signature_a << "\n\n";
        //
        // std::cout << message_b << '\n';
        // std::cout << HashFunction(message_b) << '\n';
        // std::cout << signature_b << "\n\n";

        
        bool decrypted_a = CipherMethodClass::DigitalSigValidate(signature_a, HashFunction(message_a), serverPublicKeyPath);
        bool decrypted_b = CipherMethodClass::DigitalSigValidate(signature_b, HashFunction(message_b), serverPublicKeyPath);
        
        return decrypted_a && decrypted_b;
    }


    void GetServerResponse()
    {
        boost::asio::streambuf response_buf;
        boost::system::error_code ec;

        size_t bytes_transferred = boost::asio::read(socket, response_buf, ec);
        if (ec && ec != boost::asio::error::eof) {
            std::cout << "[Client] Error reading response: " << ec.message() << '\n';
            return;
        }
        std::string response = boost::asio::buffer_cast<const char*>(response_buf.data());
        response = response.substr(0, bytes_transferred);

        std::ofstream file(responseJsonFilePath);
        if (!file.is_open()) {
            std::cout << "[Client] Cannot open file for writing response: " << responseJsonFilePath << '\n';
            return;
        }
        file << response;
        file.close();
        socket.close();
    }

    
    bool SendRequestToServer()
    {
        std::ifstream file(jsonRequestPath);
        if (!file.is_open())
        {
            std::cout << ("[Client] Cannot open JSON file: " + jsonRequestPath);
            return false;
        }
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        tcp::resolver resolver(io_context);
        boost::system::error_code ec;
        boost::asio::connect(socket, resolver.resolve("localhost", "8888"), ec);
        if (ec)
        {
            std::cout << ("[Client] Connection failed: " + ec.message());
            return false;
        }
        boost::asio::write(socket, boost::asio::buffer(content));
        return true;
    }

    
    const std::string publicKeyPath = "Digital-signature/Client/Keys/public.key";
    const std::string privateKeyPath = "Digital-signature/Client/Keys/private.key";
    const std::string serverPublicKeyPath = "Digital-signature/Client/Keys/server-public.key";

    const std::string jsonRequestPath = "Digital-signature/Client/request.json";
    const std::string responseJsonFilePath = "Digital-signature/Client/response.json";
    
    std::string Message;
    std::function<std::string(std::string)> HashFunction;
    std::string ipAddr{"localhost"};
    std::string connPort{"8888"};
    boost::asio::io_context io_context;
    tcp::socket socket;
};

