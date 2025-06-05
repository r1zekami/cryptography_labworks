#pragma once
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <boost/algorithm/string.hpp>
#include "../../hash-functions/hash-functions.h"
#include "../../alghoritms.h"

using boost::asio::ip::tcp;
using boost::multiprecision::cpp_int;

class GDSServer {
public:
    GDSServer() : io_context_(), acceptor_(io_context_, tcp::endpoint(tcp::v4(), TSA_PORT)) {}
    void Run();

private:
    bool VerifySignature(const std::string& message, cpp_int U, cpp_int E, cpp_int S, cpp_int alpha, cpp_int p, cpp_int L);
    std::string CreateTimestamp();
    void ProcessClient(const std::map<std::string, cpp_int>& public_key, const std::map<std::string, cpp_int>& private_key);

    boost::asio::io_context io_context_;
    tcp::acceptor acceptor_;
    static constexpr int TSA_PORT = 7999;
    static constexpr int PORT_RANGE_START = 8000;
    static constexpr int PORT_RANGE_END = 8002;
    void SendMsg(int port, const std::string& msg);
    std::string ListenAndReceive();

    std::string privateKeyFile = "digital-signature/group-ds/temp/group-ds-tsa/private.key";
    std::string publicKeyFile = "digital-signature/group-ds/temp/group-ds-tsa/public.key";
};

inline void GDSServer::Run() {
    std::cout << "[GDSServer] Starting TSA server on port " << TSA_PORT << "...\n";
    RSA::GenerateKeys(publicKeyFile, privateKeyFile, 600);
    std::cout << "[GDSServer] RSA keys generated.\n";
    std::map<std::string, cpp_int> public_key = ReadKey(publicKeyFile);
    std::map<std::string, cpp_int> private_key = ReadKey(privateKeyFile);
    ProcessClient(public_key, private_key);
    std::cin.get();
}

inline void GDSServer::ProcessClient( const std::map<std::string, cpp_int>& public_key, const std::map<std::string, cpp_int>& private_key) {
    
    std::string received = ListenAndReceive();
    std::cout << "[GDSServer] Received: " << received << "\n";

    std::vector<std::string> parts;
    boost::split(parts, received, boost::is_any_of(":"));
    if (parts.size() != 5 || parts[0] != "SIGNATURE") {
        std::cout << "[GDSServer] Invalid message format. Expected 5 parts, got " << parts.size() << "\n";
        //boost::asio::write(socket, boost::asio::buffer("ERROR:Invalid message format"));
        return;
    }

    std::string message = parts[1];
    cpp_int U, E, S;
    try {
        U = cpp_int("0x" + parts[2]);
        E = cpp_int("0x" + parts[3]);
        S = cpp_int("0x" + parts[4]);
    } catch (const std::exception& e) {
        std::cout << "[GDSServer] Error parsing U, E, or S: " << e.what() << "\n";
        return;
    }

    std::map<std::string, cpp_int> leaderKeys = ReadKey("digital-signature/group-ds/temp/group-ds-lead/leader.key");
    cpp_int alpha = leaderKeys["alpha"];
    cpp_int p = leaderKeys["p"];
    cpp_int L = leaderKeys["L"];

    if (!VerifySignature(message, U, E, S, alpha, p, L)) {
        std::cout << "[GDSServer] Signature verification failed\n";
        return;
    }

    std::cout << "[GDSServer] Signature verified successfully\n";

    std::string timestamp = CreateTimestamp();
    std::string data_to_hash = message + to_hex(U) + to_hex(E) + to_hex(S);
    std::string hashed_data = SHA512::hashMessage(data_to_hash);
    std::string to_sign = hashed_data + timestamp; // не хешируем здесь второй раз
    std::string signature = RSA::DigitalSigEncrypt(to_sign, privateKeyFile, SHA512::hashMessage);

    std::cout << "is it one?: " << RSA::DigitalSigValidate(hashed_data + timestamp, signature, SHA512::hashMessage, publicKeyFile) << '\n';
    
    // TIMESTAMP_RESPONSE:<message>:<U>:<E>:<S>:<Timestamp>:<Signature>:<e>:<n>
    //std::cout << "[GDSNode] concatedData:" << for_sign << "\n";
    std::cout << "[GDSServer] to_sign: " << to_sign << "\n";
    std::cout << "[GDSServer] signature: " << signature << "\n";

    //std::cout << to_hex(public_key.at("publicExponent")) << std::endl;
    //std::cout << to_hex(public_key.at("N")) << std::endl;
    
    std::string response = "TIMESTAMP_RESPONSE:"
    + message
    + ":" + to_hex(U)
    + ":" + to_hex(E)
    + ":" + to_hex(S)
    + ":" + timestamp
    + ":" + signature
    + ":" + to_hex(public_key.at("publicExponent"))
    + ":" + to_hex(public_key.at("N"));

    SendMsg(PORT_RANGE_END, response);
    std::cout << "[GDSServer] Sent response: " << response << "\n";

    return;
}

inline bool GDSServer::VerifySignature(const std::string& message, cpp_int U, cpp_int E, cpp_int S, cpp_int alpha, cpp_int p, cpp_int L) {
    std::cout << "[GDSServer] alpha: " << to_hex(alpha) << "\n";
    std::cout << "[GDSServer] p: " << to_hex(p) << "\n";
    std::cout << "[GDSServer] L: " << to_hex(L) << "\n";
    std::cout << "[GDSServer] Received U: " << to_hex(U) << "\n";
    std::cout << "[GDSServer] Received E: " << to_hex(E) << "\n";
    std::cout << "[GDSServer] Received S: " << to_hex(S) << "\n";
    
    
    cpp_int R = fast_exp_mod(U*L%p, -E, p) * fast_exp_mod(alpha, S, p) % p;
    std::cout << "[GDSServer] R: " << to_hex(R) << "\n";
    
    std::string message_hex = stringToHex(message);
    std::string data_to_hash = message_hex + to_hex(R) + to_hex(U);
    std::string hash_hex = SHA512::hashMessage(data_to_hash);
    cpp_int E_prime = cpp_int(hash_hex);

    std::cout << "[GDSServer] data_to_hash: " << data_to_hash << "\n";
    std::cout << "[GDSServer] E_prime: " << to_hex(E_prime) << "\n";

    return E_prime == E;
}


inline std::string GDSServer::CreateTimestamp() {
    boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
    std::string timestamp = boost::posix_time::to_iso_string(now);
    std::cout << "[GDSServer] Timestamp: " << timestamp << "\n";
    return timestamp;
}

inline void GDSServer::SendMsg(int port, const std::string& msg) {
    try {
        tcp::socket socket(io_context_);
        tcp::endpoint endpoint(boost::asio::ip::address::from_string("127.0.0.1"), port);
        socket.connect(endpoint);
        boost::asio::write(socket, boost::asio::buffer(msg));
        std::cout << "[GDSNode] Sent: " << msg << std::endl;
        socket.close();
    } catch (const std::exception& e) {
        std::cout << "[GDSNode] Failed to send message to port " << std::dec << port << ": " << e.what() << "\n";
    }
}

inline std::string GDSServer::ListenAndReceive() {
    tcp::socket socket(io_context_);
    std::cout << "[GDSNode] Waiting for incoming connection on port " << TSA_PORT << "...\n";
    acceptor_.accept(socket);
    std::vector<char> buffer(10256);
    boost::system::error_code ec;   
    size_t bytes_transferred = socket.read_some(boost::asio::buffer(buffer), ec);
    if (!ec && bytes_transferred > 0) {
        std::string msg(buffer.begin(), buffer.begin() + bytes_transferred);
        std::cout << "[GDSNode] Received: " << msg << "\n";
        socket.close();
        return msg;
    } else if (ec) {
        std::cout << "[GDSNode] Receive error: " << ec.message() << "\n";
    }
    socket.close();
    return "";
}