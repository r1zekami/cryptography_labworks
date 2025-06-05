#pragma once
#include <boost/asio/ip/tcp.hpp>
#include <boost/multiprecision/cpp_int.hpp>

using boost::asio::ip::tcp;
using boost::multiprecision::cpp_int;


// This class contains networking logic USED ONLY at localhost (127.0.0.1)
// Available functions:
//      std::string ListenAndRecieve(int/std::string& PORT)
//      void SendMsg(int/std::string& PORT, const std::string& msg)
//
class asioLocalNetworkingTemplate
{
public:
    asioLocalNetworkingTemplate();
    void SendMsg(int PORT, const std::string& MESSAGE_TO_SEND);
    void SendMsg(const std::string& PORT, const std::string& MESSAGE_TO_SEND);
    std::string ListenAndReceive(int PORT);
    std::string ListenAndReceive(const std::string& PORT);

    
private:
    
    boost::asio::io_context io_context;
    //tcp::acceptor acceptor;
};
