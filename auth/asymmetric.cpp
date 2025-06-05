#include "auth-client.hpp"
#include "auth-server.hpp"




void AuthClient::AsymmetricSequence()
{
    while (true) {
        std::cout << "[AuthClient] Attempting to connect to server...\n";
        PrimeNonce = GenerateNonce();
        RSA::GenerateKeys(PublicKeyPath, PrivateKeyPath, 512);

        std::string messageToEncrypt = PrimeNonce + ":" + ID;
        std::ofstream file(PlaintextPath);
        file << messageToEncrypt;
        file.close();

        std::vector<cpp_int> encryptedMessage = RSA::Encrypt(PlaintextPath, PublicKeyPath);
        std::stringstream ss;
        for (int i = 0; i < encryptedMessage.size(); i++) {
            ss << "0x" << std::hex << encryptedMessage[i];
        }
        std::string rawEncrypted = ss.str();
        std::string message = SHA256::hashMessage(PrimeNonce) + ":" + ID + ":" + rawEncrypted;

        std::cout << "[AuthClient] Sending message: " << message << std::endl;
        SendMsg(8888, message);
        std::string answer = ListenAndReceive(8888);
        if (answer.empty()) {
            std::cout << "[AuthClient] Connection failed. Want to try again? (y/n): ";
            char UserInput;
            std::cin >> UserInput;
            if (UserInput == 'n' || UserInput == 'N') {
                return;
            }
            continue;
        }
        std::cout << "[AuthClient] Received message: " << answer << std::endl;

        if (answer == PrimeNonce) {
            std::cout << "[AuthClient] AUTH SUCCESS." << std::endl;
        } else {
            std::cout << "[AuthClient] AUTH FAILED." << std::endl;
        }
        std::cin.get();
        break;
    }
}


void AuthServer::AsymmetricSequence() {
    std::string Received = ListenAndReceive(8888);
    std::cout << "[AuthServer] Received first message: " << Received << std::endl;
    std::vector<std::string> parts;
    boost::split(parts, Received, boost::is_any_of(":"));

    std::string hashed = parts[0];
    std::string ClientID = parts[1];
    std::string Ciphertext = parts[2];

    std::vector<cpp_int> ciphertextArr;
    ciphertextArr.emplace_back(cpp_int(Ciphertext));

    RSA::WriteEncryptedMessage(ciphertextArr, EncryptedTextPath);

    std::string Decrypted = RSA::Decrypt(EncryptedTextPath, PrivateKeyPath);
    std::cout << "[AuthServer] Decrypted message: " << Decrypted << std::endl;

    parts.clear();
    boost::split(parts, Decrypted, boost::is_any_of(":"));
    std::string ClientNonceVerified = parts[0];
    std::string ClientIDverified = parts[1];

    if (SHA256::hashMessage(ClientNonceVerified) == hashed && ClientIDverified == ClientID) {
        SendMsg(8888, ClientNonceVerified);
    }
}
