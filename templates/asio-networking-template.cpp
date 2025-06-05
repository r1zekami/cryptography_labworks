#include "asio-networking-template.h"

#include <boost/asio/write.hpp>


asioLocalNetworkingTemplate::asioLocalNetworkingTemplate() {}

void asioLocalNetworkingTemplate::SendMsg(const std::string& PORT, const std::string& MESSAGE_TO_SEND){
    return SendMsg(stoi(PORT), MESSAGE_TO_SEND);
}

void asioLocalNetworkingTemplate::SendMsg(int PORT, const std::string& MESSAGE_TO_SEND) {
    try {
        tcp::socket socket(io_context);
        tcp::endpoint endpoint(boost::asio::ip::address::from_string("127.0.0.1"), PORT);
        socket.connect(endpoint);
        boost::asio::write(socket, boost::asio::buffer(MESSAGE_TO_SEND));
        std::cout << "[asio] Sent: " << MESSAGE_TO_SEND << "\n";
        socket.close();
    } catch (const boost::system::system_error& e) {
        if (e.code() == boost::asio::error::connection_refused) {
            std::cout << "[asio] Failed to send message to port " << std::dec << PORT
                      << " (Connection refused)\n";
        } else {
            std::cout << "[asio] Failed to send message to port " << std::dec << PORT
                      << " (" << e.code().message() << ")\n";
        }
    }
}

std::string asioLocalNetworkingTemplate::ListenAndReceive(const std::string& PORT){
    return ListenAndReceive(stoi(PORT));
}

std::string asioLocalNetworkingTemplate::ListenAndReceive(int PORT) {
    try {
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), PORT));
        tcp::socket socket(io_context);
        std::cout << "[asio] Waiting for incoming connection on port " << PORT << "...\n";
        acceptor.accept(socket);
        std::vector<char> buffer(10256);
        boost::system::error_code ec;
        size_t bytes_transferred = socket.read_some(boost::asio::buffer(buffer), ec);
        if (!ec && bytes_transferred > 0) {
            std::string msg(buffer.begin(), buffer.begin() + bytes_transferred);
            std::cout << "[asio] Received: " << msg << "\n";
            socket.close();
            return msg;
        } else if (ec) {
            std::cout << "[asio] Receive error: " << ec.message() << "\n";
        }
        socket.close();
    } catch (const std::exception& e) {
        std::cout << "[asio] Failed to listen on port " << PORT << ": " << e.what() << "\n";
    }
    return "";
}