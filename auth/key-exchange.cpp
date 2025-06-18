#include "auth-client.hpp"
#include "auth-server.hpp"

void AuthClient::KeyExchangeSequence()
{
    RSA::GenerateKeys("auth/keys/client-public.key", "auth/keys/client-private.key");
    
    std::string ServerMessage = ListenAndReceive(8888);
    
    std::vector<std::string> ServerParts;
    boost::split(ServerParts, ServerMessage, boost::is_any_of(":"));
    std::string ID_B = ServerParts[0];
    std::string ServerModulus = ServerParts[1];
    std::string ServerExponent = ServerParts[2];
    
    std::map<std::string, cpp_int> ServerPublicKey = {{"e", cpp_int(ServerExponent)}, {"n", cpp_int(ServerModulus)}};
    std::string ServerPublicKeyPath = "auth/keys/server-public-temp.key";
    RSA::WritePublicKey(ServerPublicKey, ServerPublicKeyPath);
    
    boost::posix_time::ptime Now = boost::posix_time::second_clock::universal_time();
    std::string Timestamp = boost::posix_time::to_iso_string(Now);
    
    std::string SessionKey = "Hi_1_@m_Th3_s3$$10n_K3Y";
    
    std::string MessageToSign = ID_B + SessionKey + Timestamp;
    
    std::string SignedMessage = RSA::DigitalSigEncrypt(MessageToSign, "auth/keys/client-private.key", SHA256::hashMessage);
    
    std::string MessageToEncrypt = SessionKey + ":" + Timestamp + ":" + SignedMessage;
    
    std::string PlaintextPath = "auth/plaintext.txt";
    std::ofstream PlaintextFile(PlaintextPath);
    if (PlaintextFile.is_open()) {
        PlaintextFile << MessageToEncrypt;
        PlaintextFile.close();
    }
    
    std::vector<cpp_int> Ciphertext = RSA::Encrypt(PlaintextPath, ServerPublicKeyPath);
    
    std::string EncryptedTextPath = "auth/encrypted.txt";
    RSA::WriteEncryptedMessage(Ciphertext, EncryptedTextPath);
    
    std::ifstream File(EncryptedTextPath);
    std::stringstream Ss;
    Ss << File.rdbuf();
    std::string EncryptedMessage = Ss.str();
    File.close();
    
    auto ClientKey = ReadKey("auth/keys/client-public.key");
    std::string ClientModulus = boost::lexical_cast<std::string>(ClientKey["N"]);
    std::string ClientExponent = boost::lexical_cast<std::string>(ClientKey["publicExponent"]);
    std::string MessageToSend = ClientModulus + ":" + ClientExponent + ":" + EncryptedMessage;
    
    SendMsg(8888, MessageToSend);
    
    std::string Result = ListenAndReceive(8888);
    std::cout << "[AuthClient] Result: " << Result << "\n";
    std::cout << "[AuthClient] Key: " << SessionKey << "\n";
}

void AuthServer::KeyExchangeSequence()
{
    RSA::GenerateKeys("auth/keys/server-public.key", "auth/keys/server-private.key");
    
    auto Key = ReadKey("auth/keys/server-public.key");
    std::string Modulus = boost::lexical_cast<std::string>(Key["N"]);
    std::string Exponent = boost::lexical_cast<std::string>(Key["publicExponent"]);
    std::cout << Exponent << "\n";
    std::string ID_B = "Bob";
    std::string MessageToSend = ID_B + ":" + Modulus + ":" + Exponent;
    SendMsg(8888, MessageToSend);
        
    std::string ClientMessage = ListenAndReceive(8888);
    
    std::vector<std::string> Parts;
    boost::split(Parts, ClientMessage, boost::is_any_of(":"));
    std::string ClientModulus = Parts[0];
    std::string ClientExponent = Parts[1];
    std::string Encrypted = boost::join(std::vector<std::string>(Parts.begin() + 2, Parts.end()), ":");
    
    std::string EncryptedTextPath = "auth/encrypted.txt";
    std::ofstream File(EncryptedTextPath);
    if (File.is_open()) {
        File << Encrypted;
        File.close();
    }
    
    std::string DecryptedMessage = RSA::Decrypt(EncryptedTextPath, "auth/keys/server-private.key");
    
    std::vector<std::string> DecryptedParts;
    boost::split(DecryptedParts, DecryptedMessage, boost::is_any_of(":"));
    std::string SessionKey = DecryptedParts[0];
    std::string Timestamp = DecryptedParts[1];
    std::string Sign = DecryptedParts[2];
    
    std::map<std::string, cpp_int> ClientPublicKey = {{"e", cpp_int(ClientExponent)}, {"n", cpp_int(ClientModulus)}};
    std::string ClientPublicKeyPath = "auth/keys/client-public-temp.key";
    RSA::WritePublicKey(ClientPublicKey, ClientPublicKeyPath);
    
    std::string MessageToCheck = ID_B + SessionKey + Timestamp;
    bool Result = RSA::DigitalSigValidate(MessageToCheck, Sign, SHA256::hashMessage, ClientPublicKeyPath);
    
    if (Result) {
        SendMsg(8888, "Key exchange successful");
        std::cout << "[AuthClient] Key: " << SessionKey << "\n";
    } else {
        SendMsg(8888, "Key exchange failed");
    }
}