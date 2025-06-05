#include "auth-client.hpp"
#include "auth-server.hpp"

void AuthClient::TwoPassSymmetricSequence()
{
    std::string Nonce = GenerateNonce();
    PrimeNonce = Nonce;
    std::string InitMessage = CreateInitMessage(Nonce);
    std::cout << "[AuthClient] Sending request to server...\n";
    SendMsg(8888, InitMessage);
    std::cout << "[AuthClient] Successfully sent request to server.\n";
    std::string ServerResponse = ListenAndReceive(8888);
    std::cout << "[AuthClient] Server response: " << ServerResponse << "\n";
    std::string ResponseEncryptedPart = ServerResponse.substr(ServerResponse.find(':') + 1);
    auto AESDecryptedBytes = aes.DecryptCBC(hexStringToBytes(ResponseEncryptedPart), Key, IV);
    std::string AESDecrypted = BytesToText(AESDecryptedBytes);
    std::cout << "[AuthClient] Decrypted response: " << AESDecrypted << std::endl;

    std::string DecryptedNonce = AESDecrypted.substr(0, AESDecrypted.find(':'));
    std::cout << "[AuthClient] Decrypted nonce: " << DecryptedNonce << std::endl;

    if (PrimeNonce == DecryptedNonce) {
        std::cout << "[AuthClient] Auth verified\n";
    } else {
        std::cout << "[AuthClient] Wrong nonce, auth denied\n";
    }
    std::cin.get();
    return;
}


void AuthServer::TwoPassSymmetricSequence()
{
    try {
        std::string Received = ListenAndReceive(8888);
        std::cout << "[AuthServer] Received: " << Received << std::endl;
        std::string M2 = Received.substr(0, Received.find(':'));
        std::string AESEncrypted = Received.substr(Received.find(':') + 1);
        auto AESEncryptedBytes = hexStringToBytes(AESEncrypted);
        auto AESDecryptedBytes = aes.DecryptCBC(AESEncryptedBytes, Key, IV);
        std::string AESDecrypted = BytesToText(AESDecryptedBytes);
        std::cout << "[AuthServer] Client AES Decrypted: " << AESDecrypted << std::endl;
        std::string ClientNonce = AESDecrypted.substr(0, AESDecrypted.find(':'));

        std::cin.clear();
        std::string userInputM3;
        std::cout << "[AuthServer] Enter message (M3): ";
        std::cin >> userInputM3;

        std::string ResponseMessage = CreateResponseMessage(ClientNonce, userInputM3);
        std::cout << "[AuthServer] Response: " << ResponseMessage << std::endl;
        SendMsg(8888, ResponseMessage);
        std::cout << "[AuthServer] Response sent" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[AuthServer] Client handling error: " << e.what() << std::endl;
    }
}

