#include "auth-client.hpp"
#include "auth-server.hpp"
#include "../hash-functions/hash-functions.h"
#include "../cipher-systems/ELGAMAL/elgamal.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>

using cpp_int = boost::multiprecision::cpp_int;

const int N = 10; //Hash chain length

void AuthClient::SPEKE_Sequence()
{
    cpp_int p = generate_prime(512);
    while (true) {
        std::cout << "[AuthClient] Choose action:\n1. Register\n2. Authenticate\n3. Exit\n";
        int Choice;
        std::cin >> Choice;
        if (Choice == 1) {
            std::string HashFunctionName = ChooseHashFunction();
            std::string Password = GetPassword();
            std::vector<std::string> HashChain = GenerateHashChain(Password, N);
            std::string FinalHash = HashChain.back();
            std::string Request = "REGISTER:" + ID + ":" + HashFunctionName + ":" + std::to_string(N) + ":" + FinalHash;
            std::cout << "[AuthClient] Sending registration request: " << Request << "\n";
            SendMsg(8888, Request);
            std::string Response = ListenAndReceive(8888);
            std::cout << "[AuthClient] Server response: " << Response << "\n";
            if (Response == "REGISTRATION_SUCCESS") {
                StoredHashChain = HashChain;
                InternalCounter = 0;
            }
        } else if (Choice == 2) {
            std::string OneTimePassword = "EMPTY";
            if (!StoredHashChain.empty() && InternalCounter < StoredHashChain.size() - 1) {
                OneTimePassword = StoredHashChain[StoredHashChain.size() - 2 - InternalCounter];
            }
            std::string Request = "AUTHENTICATE:" + ID + ":" + std::to_string(InternalCounter) + ":" + OneTimePassword;
            std::cout << "[AuthClient] Sending authentication request: " << Request << "\n";
            SendMsg(8888, Request);
            std::string Response = ListenAndReceive(8888);
            std::cout << "[AuthClient] Server response: " << Response << "\n";
            if (Response == "AUTH_SUCCESS") {
                // compute g from one-time password
                std::cout << OneTimePassword << "\n";
                cpp_int w = cpp_int(OneTimePassword);
                cpp_int g = fast_exp_mod(w, 2, p); //(W * W) % P;
                SendMsg(8888, to_hex(p) + ":" + to_hex(g));
                std::cout << "[AuthClient] Sent p and g\n";
                boost::random::mt19937 Gen(std::random_device{}());
                boost::random::uniform_int_distribution<cpp_int> x_dist(1, p - 1);
                cpp_int x = x_dist(Gen);
                cpp_int alpha = fast_exp_mod(g, x, p);
                SendMsg(8888, to_hex(alpha));
                std::cout << "[AuthClient] Sent alpha\n";
                std::string betaStr = ListenAndReceive(8888);
                cpp_int beta = cpp_int("0x" + betaStr);
                cpp_int k = fast_exp_mod(beta, x, p);
                std::cout << "[AuthClient] Session key: " << std::hex << k << "\n";
                InternalCounter++;
            }
        } else if (Choice == 3) {
            break;
        } else {
            std::cout << "[AuthClient] Invalid choice\n";
        }
    }
}

void AuthServer::SPEKE_Sequence()
{
    while (true) {
        std::string Received = ListenAndReceive(8888);
        std::cout << "[AuthServer] Received request: " << Received << "\n";
        std::vector<std::string> Parts;
        boost::split(Parts, Received, boost::is_any_of(":"));
        if (Parts.size() < 2) {
            SendMsg(8888, "INVALID_REQUEST");
            continue;
        }

        std::string Command = Parts[0];
        std::string ClientID = Parts[1];

        if (Command == "REGISTER") {
            if (Parts.size() != 5) {
                SendMsg(8888, "INVALID_REQUEST");
                continue;
            }
            std::string HashFunctionName = Parts[2];
            int ChainLength = std::stoi(Parts[3]);
            std::string FinalHash = Parts[4];
            RegisterClient(ClientID, HashFunctionName, ChainLength, FinalHash);
            SendMsg(8888, "REGISTRATION_SUCCESS");
        } else if (Command == "AUTHENTICATE") {
            if (Parts.size() != 4) {
                SendMsg(8888, "INVALID_REQUEST");
                continue;
            }
            int Attempt = std::stoi(Parts[2]);
            std::string OneTimePassword = Parts[3];
            std::string Result = AuthenticateClient(ClientID, Attempt, OneTimePassword);
            SendMsg(8888, Result);
            if (Result == "AUTH_SUCCESS") {
                std::string pgStr = ListenAndReceive(8888);
                std::vector<std::string> pgParts;
                boost::split(pgParts, pgStr, boost::is_any_of(":"));
                cpp_int p = cpp_int("0x" + pgParts[0]);
                cpp_int g = cpp_int("0x" + pgParts[1]);
                std::string alphaStr = ListenAndReceive(8888);
                cpp_int alpha = cpp_int("0x" + alphaStr);
                boost::random::mt19937 gen(std::random_device{}());
                boost::random::uniform_int_distribution<cpp_int> y_dist(1, p - 1);
                cpp_int y = y_dist(gen);
                cpp_int beta = fast_exp_mod(g, y, p);
                SendMsg(8888, to_hex(beta));
                std::cout << "[AuthServer] Sent beta\n";
                cpp_int k = fast_exp_mod(alpha, y, p);
                std::cout << "[AuthServer] Session key: " << std::hex << k << "\n";
            }
        } else {
            SendMsg(8888, "UNKNOWN_COMMAND");
        }
    }
}