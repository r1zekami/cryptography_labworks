#include "auth-client.hpp"
#include "auth-server.hpp"
#include "../cipher-systems/ELGAMAL/elgamal.h"


void AuthClient::DiffieHellmanSequence() {
    
    //std::string SessionKey = "Hi_1_@m_Th3_s3$$10n_K3Y";
    
    cpp_int p = generate_prime(256);
    cpp_int g = ELGAMAL::findPrimitive(p);

    SendMsg(8888, to_hex(p) + ":" + to_hex(g));
    
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> x_dist(2, p-2);
    
    cpp_int x = x_dist(gen);
    cpp_int alpha = fast_exp_mod(g, x, p);

    SendMsg(8888, to_hex(alpha));

    std::string betaStr = ListenAndReceive(8888);

    cpp_int beta = cpp_int("0x" + betaStr);

    cpp_int k = fast_exp_mod(beta, x, p);

    std::cout << "[AuthClient] Key: " << std::hex << k << "\n";
    return;
}

void AuthServer::DiffieHellmanSequence() {

    // Technically p and g already there but i need to pass it like this
    std::string pgStr = ListenAndReceive(8888);
    std::string alphaStr = ListenAndReceive(8888);
    
    std::vector<std::string> Parts;
    boost::split(Parts, pgStr, boost::is_any_of(":"));

    cpp_int p = cpp_int("0x" + Parts[0]);
    cpp_int g = cpp_int("0x" + Parts[1]);
    cpp_int alpha = cpp_int("0x" + alphaStr);

    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> y_dist(2, p-2);
    cpp_int y = y_dist(gen);
    
    cpp_int beta = fast_exp_mod(g, y, p);
    SendMsg(8888, to_hex(beta));

    cpp_int k = fast_exp_mod(alpha, y, p);

    std::cout << "[AuthServer] Key: " << std::hex << k << "\n";
    return;
}

