#include "auth-client.hpp"
#include "auth-server.hpp"

void AuthClient::KeyExchangeSequence()
{
    RSA::GenerateKeys(PublicKeyPath, PrivateKeyPath);
    
    std::string SessionKey = "Hi_1_@m_Th3_s3$$10n_K3Y";
    auto B_PublicKey = ReadKey(PublicKeyPath);

    boost::posix_time::ptime Now = boost::posix_time::second_clock::universal_time();
    std::string Timestamp = boost::posix_time::to_iso_string(Now);

    std::string B_ID = "Bob";
    std::string MessageToSign = B_ID + Timestamp + SessionKey;

    std::string SignedMessage = RSA::DigitalSigEncrypt(MessageToSign, PrivateKeyPath, SHA256::hashMessage);

    std::cout << "[AuthClient] Signed: " << SignedMessage << "\n";
    
    std::string MessageToEncrypt = SessionKey + ":" + Timestamp + ":" + SignedMessage;

    std::ofstream PlaintextFile(PlaintextPath);
    if (PlaintextFile.is_open()) {
        PlaintextFile << MessageToEncrypt;
        PlaintextFile.close();
    }

    std::vector<cpp_int> Ciphertext = RSA::Encrypt(PlaintextPath, PublicKeyPath);
    RSA::WriteEncryptedMessage(Ciphertext, EncryptedTextPath);

    std::ifstream File(EncryptedTextPath);
    std::stringstream Ss;
    Ss << File.rdbuf();
    std::string EncryptedMessage = Ss.str();
    File.close();

    SendMsg(8888, EncryptedMessage);
    std::cout << "[AuthClient] Sent encrypted message\n";

    std::string Result = ListenAndReceive(8888);
    std::cout << "[AuthClient] Result: " << Result << "\n";
}

void AuthServer::KeyExchangeSequence()
{
    std::string ClientMessage = ListenAndReceive(8888);

    std::ofstream File(EncryptedTextPath);
    if (File.is_open()) {
        File << ClientMessage;
        File.close();
        std::cout << "[AuthServer] Wrote received message to " << EncryptedTextPath << "\n";
    }

    std::string DecryptedMessage = RSA::Decrypt(EncryptedTextPath, PrivateKeyPath);
    std::cout << "[AuthServer] Decrypted: " << DecryptedMessage << "\n";
    
    std::vector<std::string> Parts;
    boost::split(Parts, DecryptedMessage, boost::is_any_of(":"));

    std::string SessionKey = Parts[0];
    std::string Timestamp = Parts[1];
    std::string SignedMessage = Parts[2];
    
    std::string MessageToCheck = ID + Timestamp + SessionKey;

    bool Result = RSA::DigitalSigValidate(MessageToCheck, SignedMessage, SHA256::hashMessage, PublicKeyPath);
    

    if (Result) {
        std::cout << "[AuthServer] Key exchange successful: " << SessionKey << "\n";
        SendMsg(8888, "Key exchange successful\n");
    } else {
        std::cout << "[AuthServer] Key exchange failed\n";
        SendMsg(8888, "Key exchange failed\n");
    }
}