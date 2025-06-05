#include "auth-client.hpp"
#include "auth-server.hpp"



void AuthClient::SingleUsePasswordSequence()
{
    while (true) {
        std::cout << "[AuthClient] Choose action:\n1. Register\n2. Authenticate\n3. Exit\n";
        int choice;
        std::cin >> choice;
        if (choice == 1) {
            std::string hashFunctionName = ChooseHashFunction();
            std::string password = GetPassword();
            std::cout << "[AuthClient] Enter number of passwords (N): ";
            int N;
            std::cin >> N;
            std::vector<std::string> hashChain = GenerateHashChain(password, N);
            std::string finalHash = hashChain.back();
            std::string request = "REGISTER:" + ID + ":" + hashFunctionName + ":" + std::to_string(N) + ":" + finalHash;
            std::cout << "[AuthClient] Sending registration request: " << request << std::endl;
            SendMsg(8888, request);
            std::string response = ListenAndReceive(8888);
            std::cout << "[AuthClient] Server response: " << response << std::endl;
            if (response == "REGISTRATION_SUCCESS") {
                StoredHashChain = hashChain;
                InternalCounter = 0;
            }
        } else if (choice == 2) {
            std::string oneTimePassword = "EMPTY";
            if (!StoredHashChain.empty() && InternalCounter < StoredHashChain.size() - 1) {
                oneTimePassword = StoredHashChain[StoredHashChain.size() - 2 - InternalCounter];
            }
            std::string request = "AUTHENTICATE:" + ID + ":" + std::to_string(InternalCounter) + ":" + oneTimePassword;
            std::cout << "[AuthClient] Sending authentication request: " << request << std::endl;
            SendMsg(8888, request);
            std::string response = ListenAndReceive(8888);
            std::cout << "[AuthClient] Server response: " << response << std::endl;
            if (response == "AUTH_SUCCESS") {
                InternalCounter++;
            }
        } else if (choice == 3) {
            break;
        } else {
            std::cout << "[AuthClient] Invalid choice\n";
        }
    }
}


void AuthServer::SingleUsePasswordSequence()
{
    std::string Received = ListenAndReceive(8888);
    std::cout << "[AuthServer] Received request: " << Received << std::endl;
    std::vector<std::string> parts;
    boost::split(parts, Received, boost::is_any_of(":"));
    if (parts.size() < 2) {
        SendMsg(8888, "INVALID_REQUEST");
        return;
    }

    std::string command = parts[0];
    std::string clientID = parts[1];

    if (command == "REGISTER") {
        if (parts.size() != 5) {
            SendMsg(8888, "INVALID_REQUEST");
            return;
        }
        std::string hashFunctionName = parts[2];
        int N = std::stoi(parts[3]);
        std::string finalHash = parts[4];
        RegisterClient(clientID, hashFunctionName, N, finalHash);
        SendMsg(8888, "REGISTRATION_SUCCESS");
    } else if (command == "AUTHENTICATE") {
        if (parts.size() != 4) {
            SendMsg(8888, "INVALID_REQUEST");
            return;
        }
        int attempt = std::stoi(parts[2]);
        std::string oneTimePassword = parts[3];
        std::string result = AuthenticateClient(clientID, attempt, oneTimePassword);
        SendMsg(8888, result);
    } else {
        SendMsg(8888, "UNKNOWN_COMMAND");
    }
}