#include "auth-client.hpp"
#include "auth-server.hpp"
#include <iostream>

void AuthClient::FiatShamirSequence()
{
    cpp_int p = generate_prime(256);
    cpp_int q = generate_prime(256);
    while (true) {
        if (p == q) {
            q = generate_prime(256);
        } else { break; }
    }
    cpp_int n = p * q;
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> s_dist(1, n - 1);
    
    cpp_int s;
    while (true) {
        s = s_dist(gen);
        if (std::get<0>(extended_euclidean_alg(s, n)) == 1) {
            break;
        }
    }
    
    cpp_int v = fast_exp_mod(s, 2, n);

    // send n and v
    std::string nRequest = to_hex(n);
    std::string vRequest = to_hex(v);
    SendMsg(8888, nRequest + ":" + vRequest);

    std::string Response = ListenAndReceive(8888);
    if (Response != "V_ACHIEVED") {
        std::cout << "[AuthClient] Failed to receive V_ACHIEVED\n";
        return;
    }

    // 10 rounds
    for (int i = 0; i < 10; ++i) {
        boost::random::uniform_int_distribution<cpp_int> z_dist(1, n - 1);
        cpp_int z = z_dist(gen);
        cpp_int x = fast_exp_mod(z, 2, n);

        SendMsg(8888, to_hex(x));

        std::string cResponse = ListenAndReceive(8888);
        cpp_int c = cpp_int("0x" + cResponse);

        cpp_int y = 0;
        if (c == 0) {
            y = z;
        } else if (c == 1) {
            y = (z * s) % n;
        }
        
        SendMsg(8888, to_hex(y));
    }
    std::cout << "[AuthClient] Auth successful\n";
}

void AuthServer::FiatShamirSequence()
{
    // receive n and v
    std::string InitRequest = ListenAndReceive(8888);
    std::vector<std::string> Parts;
    boost::split(Parts, InitRequest, boost::is_any_of(":"));
    std::string nStr = Parts[0];
    std::string vStr = Parts[1];
    cpp_int n = cpp_int("0x" + nStr);
    cpp_int v = cpp_int("0x" + vStr);

    SendMsg(8888, "V_ACHIEVED");

    // 10 verification rounds
    for (int i = 0; i < 10; ++i) {
        std::string xResponse = ListenAndReceive(8888);
        cpp_int x = cpp_int("0x" + xResponse);

        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<cpp_int> c_dist(0, 1);
        cpp_int c = c_dist(gen);
        
        SendMsg(8888, to_hex(c));

        std::string yResponse = ListenAndReceive(8888);
        cpp_int y = cpp_int("0x" + yResponse);

        // y^2 mod n == x * v^c mod n
        if (y != 0 && fast_exp_mod(y, 2, n) == (x * fast_exp_mod(v, c, n)) % n) {
            std::cout << "[AuthServer] Check " << i + 1 << " passed\n";
            continue;
        } else {
            std::cout << "[AuthServer] Check " << i + 1 << " failed\n";
            return;
        }
    }
    std::cout << "[AuthServer] Auth successful\n";
}