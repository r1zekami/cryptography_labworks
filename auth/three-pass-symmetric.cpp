#include "auth-client.hpp"
#include "auth-server.hpp"


void AuthClient::ThreePassSymmetricSequence()
{
    std::string Ra = GenerateNonce();
            std::string M1 = "MESSAGE1";
            std::string first_message = Ra + ":" + M1;
            std::cout << "[AuthClient] Sending first message: " << first_message << std::endl;
            SendMsg(8888, first_message);
            std::string second_message = ListenAndReceive(8888);
            std::cout << "[AuthClient] Received second message: " << second_message << std::endl;

            size_t pos = second_message.find(':');
            if (pos == std::string::npos) {
                std::cout << "[AuthClient] Invalid second message format\n";
                return;
            }
            std::string M3 = second_message.substr(0, pos);
            std::string encrypted = second_message.substr(pos + 1);
            auto encrypted_bytes = hexStringToBytes(encrypted);
            auto decrypted_bytes = aes.DecryptCBC(encrypted_bytes, Key, IV);
            std::string decrypted = BytesToText(decrypted_bytes);
            std::cout << "[AuthClient] Decrypted second message: " << decrypted << std::endl;

            std::vector<std::string> parts;
            boost::split(parts, decrypted, boost::is_any_of(":"));
            if (parts.size() != 4) {
                std::cout << "[AuthClient] Invalid decrypted message format\n";
                return;
            }
            std::string Ra_prime = parts[0];
            std::string Rb = parts[1];
            std::string B = parts[2];
            std::string M2 = parts[3];
            if (Ra_prime != Ra) {
                std::cout << "[AuthClient] Authentication failed: Nonce (Ra) mismatch\n";
                return;
            }
            std::cout << "[AuthClient] Verified server response. Rb: " << Rb << ", B: " << B << ", M2: " << M2 << std::endl;

            std::string M4 = "MESSAGE4";
            std::string M5 = "MESSAGE5";
            std::string to_encrypt = Rb + ":" + Ra + ":" + ID + ":" + M4;
            std::cout << "[AuthClient] Third message data: " << M5 << ":" << to_encrypt << std::endl;
            auto to_encrypt_bytes = stringToBytes(to_encrypt);
            auto ciphertext_bytes = aes.EncryptCBC(to_encrypt_bytes, Key, IV);
            std::string ciphertext = BytesToHexString(ciphertext_bytes);
            std::string third_message = M5 + ":" + ciphertext;
            std::cout << "[AuthClient] Sending third message: " << third_message << std::endl;
            SendMsg(8888, third_message);
            std::string final_response = ListenAndReceive(8888);
            std::cout << "[AuthClient] Server final response: " << final_response << std::endl;
            std::cin.get();
}



void AuthServer::ThreePassSymmetricSequence()
{
    std::string Received = ListenAndReceive(8888);
            std::cout << "[AuthServer] Received first message: " << Received << std::endl;
            std::vector<std::string> parts;
            boost::split(parts, Received, boost::is_any_of(":"));
            if (parts.size() != 2) {
                std::cout << "[AuthServer] Invalid first message format\n";
                return;
            }
            std::string Ra = parts[0];
            std::string M1 = parts[1];

            std::string Rb = GenerateNonce();
            std::string M2 = "MESSAGE2";
            std::string M3 = "MESSAGE3";
            std::string to_encrypt = Ra + ":" + Rb + ":" + ID + ":" + M2;
            std::cout << "[AuthServer] " << M3 << ":" << to_encrypt << std::endl;
            auto to_encrypt_bytes = stringToBytes(to_encrypt);
            auto ciphertext_bytes = aes.EncryptCBC(to_encrypt_bytes, Key, IV);
            std::string ciphertext = BytesToHexString(ciphertext_bytes);
            std::string second_message = M3 + ":" + ciphertext;
            std::cout << "[AuthServer] Sending second message: " << second_message << std::endl;
            SendMsg(8888, second_message);

            std::string third_message = ListenAndReceive(8888);
            std::cout << "[AuthServer] Received third message: " << third_message << std::endl;
            size_t pos = third_message.find(':');
            if (pos == std::string::npos) {
                std::cout << "[AuthServer] Invalid third message format\n";
                SendMsg(8888, "AUTH_FAILURE");
                return;
            }
            std::string M5 = third_message.substr(0, pos);
            std::string encrypted_third = third_message.substr(pos + 1);
            auto encrypted_bytes_third = hexStringToBytes(encrypted_third);
            auto decrypted_bytes_third = aes.DecryptCBC(encrypted_bytes_third, Key, IV);
            std::string decrypted_third = BytesToText(decrypted_bytes_third);
            std::cout << "[AuthServer] Decrypted third message: " << decrypted_third << std::endl;
            std::vector<std::string> parts_third;
            boost::split(parts_third, decrypted_third, boost::is_any_of(":"));
            if (parts_third.size() != 4) {
                std::cout << "[AuthServer] Invalid decrypted third message format\n";
                SendMsg(8888, "AUTH_FAILURE");
                return;
            }
            std::string Rb_prime = parts_third[0];
            std::string Ra_prime = parts_third[1];
            std::string A = parts_third[2];
            std::string M4 = parts_third[3];

            if (Rb_prime == Rb && Ra_prime == Ra) {
                std::cout << "[AuthServer] Authentication successful for client " << A << std::endl;
                SendMsg(8888, "AUTH_SUCCESS");
            } else {
                std::cout << "[AuthServer] Authentication failed\n";
                SendMsg(8888, "AUTH_FAILURE");
            }
}