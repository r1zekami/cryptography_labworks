#include "group-ds-node.hpp"

void GDSNode::SendMsg(int port, const std::string& msg) {
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


void GDSNode::StartListen() {
    std::cout << "[GDSNode] Listening on port: " << std::dec << my_port_ << "...\n";
    while (true) {
        tcp::socket socket(io_context_);
        std::cout << "[GDSNode] Waiting for incoming connection on port "  << std::dec << my_port_ << "...\n";
        acceptor_.accept(socket);
        std::cout << "[GDSNode] Connection accepted from " << socket.remote_endpoint() << "\n";
        socket.close();
    }
}

void GDSNode::SelectPort() {
    std::cout << "[GDSNode] Starting port selection process...\n";
    for (int port = PORT_RANGE_START; port <= PORT_RANGE_END; ++port) {
        try {
            acceptor_.open(tcp::v4());
            acceptor_.bind(tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), port));
            acceptor_.listen();
            my_port_ = port;
            std::cout << "[GDSNode] Successfully bound to port: " << std::dec << my_port_ << "\n";
            return;
        } catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::address_in_use) {
                std::cout << "[GDSNode] Port " << port << " is in use, trying next...\n";
                acceptor_.close();
                continue;
            } else {
                std::cout << "[GDSNode] Error: " << e.what() << "\n";
                return;
            }
        }
    }
    std::cout << "[GDSNode] Error: All ports in range are occupied!\n";
    my_port_ = -1;
}

std::string GDSNode::ListenAndReceive() {
    tcp::socket socket(io_context_);
    std::cout << "[GDSNode] Waiting for incoming connection on port " << my_port_ << "...\n";
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