#pragma once
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


using boost::asio::ip::tcp;

template<typename CipherMethodClass, typename HashFunctionClass>
class DSClient {
    public:

    DSClient( std::string ipAddress,
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

        //plaki plaki
        if (CipherMethodClass::GetName() == "FIAT_SHAMIR")
            CipherMethodClass::GenerateKeys(publicKeyPath, privateKeyPath, HashFunctionClass::GetOutputHashSize());
        else
            CipherMethodClass::GenerateKeys(publicKeyPath, privateKeyPath);
        //ну тут надо подумать как то как сдлеать пока пофик
        
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
        boost::property_tree::ptree Root;
        Root.put("CMSVersion", "1");
        Root.put("DigestAlgorithmIdentifiers", HashFunctionClass::GetName());
        boost::property_tree::ptree EncapsulatedContentInfo;
        EncapsulatedContentInfo.put("ContentType", "Data");
        EncapsulatedContentInfo.put("OCTET_STRING_OPTIONAL", Message);
        Root.add_child("EncapsulatedContentInfo", EncapsulatedContentInfo);

        boost::property_tree::ptree SignerInfos;
        SignerInfos.put("CMSVersion", "1");
        SignerInfos.put("SignerIdentifier", "R1ZEKAMI");
        SignerInfos.put("DigestAlgorithmIdentifiers", HashFunctionClass::GetName());
        SignerInfos.put("SignatureAlgorithmIdentifier", CipherMethodClass::GetName());
        SignerInfos.put("SignatureValue", CipherMethodClass::DigitalSigEncrypt(Message, privateKeyPath, HashFunction));
        SignerInfos.add_child("SubjectPublicKeyInfo", CipherMethodClass::GetPublicKeyNode(publicKeyPath));
        boost::property_tree::ptree UnsignedAttributes;
        UnsignedAttributes.put("ObjectIdentifier", "signature-time-stamp");
        boost::property_tree::ptree SetOfAttributeValue;
        UnsignedAttributes.add_child("SET_OF_AttributeValue", SetOfAttributeValue);
        SignerInfos.add_child("UnsignedAttributes", UnsignedAttributes);

        Root.add_child("SignerInfos", SignerInfos);
        boost::property_tree::write_json(jsonRequestPath, Root, std::locale(), true);
    }

    
    bool ValidateResponse(std::string ResponseJsonFilePath)
    {
        boost::property_tree::ptree pt;
        std::ifstream file(ResponseJsonFilePath);
        if (!file.is_open()) {
            std::cout << "[Client] Cannot open response file: " << ResponseJsonFilePath << '\n';
            return false;
        }

        file.seekg(0, std::ios::end);
        if (file.tellg() == 0) {
            std::cout << "[Client] Response file is empty. Validation failed\n";
            file.close();
            return false;
        }
        file.seekg(0, std::ios::beg);
        
        boost::property_tree::read_json(file, pt);
        file.close();

        std::string message_a = pt.get<std::string>("EncapsulatedContentInfo.OCTET_STRING_OPTIONAL"); // plaintext
        std::string signature_a = pt.get<std::string>("SignerInfos.SignatureValue"); // client's signature
        std::string timestamp = pt.get<std::string>("SignerInfos.UnsignedAttributes.SET_OF_AttributeValue.Timestamp");
        std::string server_signature = pt.get<std::string>("SignerInfos.UnsignedAttributes.SET_OF_AttributeValue.ServerSignature");
        boost::property_tree::ptree server_public_key_node = pt.get_child("SignerInfos.UnsignedAttributes.SET_OF_AttributeValue.ServerPublicKeyInfo");

        std::map<std::string, cpp_int> server_public_key_container = CipherMethodClass::GetPublicKeyContainer(server_public_key_node);
        CipherMethodClass::WritePublicKey(server_public_key_container, serverPublicKeyPath);

        bool client_signature_valid = CipherMethodClass::DigitalSigValidate(message_a, signature_a, HashFunction, publicKeyPath);
        std::string message_for_server_sig = message_a + signature_a + timestamp;
        bool server_signature_valid = CipherMethodClass::DigitalSigValidate(message_for_server_sig, server_signature, HashFunction, serverPublicKeyPath);

        return client_signature_valid && server_signature_valid;
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

    
    const std::string publicKeyPath =        "digital-signature/ds/ds-client/keys/public.key";
    const std::string privateKeyPath =       "digital-signature/ds/ds-client/keys/private.key";
    const std::string serverPublicKeyPath =  "digital-signature/ds/ds-client/keys/server-public.key";
    const std::string jsonRequestPath =      "digital-signature/ds/ds-client/request.json";
    const std::string responseJsonFilePath = "digital-signature/ds/ds-client/response.json";
    
    std::string Message;
    std::function<std::string(std::string)> HashFunction;
    std::string ipAddr{"localhost"};
    std::string connPort{"8888"};
    boost::asio::io_context io_context;
    tcp::socket socket;
};

