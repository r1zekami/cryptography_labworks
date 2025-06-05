#pragma once
#include <boost/asio.hpp>
#include "../../alghoritms.h"

using boost::asio::ip::tcp;

// Group Digital Signature Node example. Acting both Client and Leader.
// The last counted Node will act as Leader.
class GDSNode {
    static constexpr int TSA_PORT = 7999;
    static constexpr int PORT_RANGE_START = 8000;
    static constexpr int PORT_RANGE_END = 8002;
    static constexpr int NODE_COUNT = PORT_RANGE_END - PORT_RANGE_START + 1;

    bool isAuthor{false};
    
public:
    GDSNode() : io_context_(), acceptor_(io_context_), my_port_(-1) {}
    void Run();

private:

    //net code
    void SelectPort();
    void StartListen();
    void SendMsg(int port, const std::string& msg);
    std::string ListenAndReceive();

public:
    class GDSCrypto {
        public:
        static std::map<std::string, cpp_int> GenerateLeaderKeys();
        static void GenerateAndSaveLeaderKeys();
        static std::map<std::string, cpp_int> GenerateMemberKeys(cpp_int alpha, cpp_int p, cpp_int q);
    };
private:
    
    //leader
    void Leader();
    std::string leaderKeysPath = "digital-signature/group-ds/temp/group-ds-lead/leader.key";
    bool VerifyAndChooseViolence();
    //--

    //member
    void Member();
    std::string memberKeysPath = "digital-signature/group-ds/temp/group-ds-mem/";
    //--
    
    boost::asio::io_context io_context_;
    tcp::acceptor acceptor_;
    int my_port_;
    //std::map<int, std::unique_ptr<tcp::socket>> sockets_;
};


