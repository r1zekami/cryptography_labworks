#include "group-ds-node.hpp"
#include "../../cipher-systems/ELGAMAL/elgamal.h"


std::map<std::string, cpp_int> GDSNode::GDSCrypto::GenerateMemberKeys(cpp_int alpha, cpp_int p, cpp_int q)
{
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> k_dist(1, q - 1);
    cpp_int k = k_dist(gen);
    cpp_int P = fast_exp_mod(alpha, k, p);
    std::map<std::string, cpp_int> keys;
    keys["k"] = k; keys["P"] = P;
    return keys;
}


void GDSNode::GDSCrypto::GenerateAndSaveLeaderKeys()
{
    std::cout << "[GDSNode::GDSCrypto] Generating leader keys..." << std::endl;
    std::string leaderKeysPath = "digital-signature/group-ds/temp/group-ds-lead/leader.key";
    std::map<std::string, cpp_int> LeaderKeys = GenerateLeaderKeys();
    std::ofstream leaderKeyFile(leaderKeysPath);
    leaderKeyFile << "gdsiLeaderKeys {\n";
    leaderKeyFile << "    p     "     << LeaderKeys["p"]     << "\n";
    leaderKeyFile << "    q     "     << LeaderKeys["q"]     << "\n";
    leaderKeyFile << "    alpha " << LeaderKeys["alpha"] << "\n";
    leaderKeyFile << "    z     "     << LeaderKeys["z"]     << "\n";
    leaderKeyFile << "    L     "     << LeaderKeys["L"]     << "\n";
    leaderKeyFile << "    n     "     << LeaderKeys["n"]     << "\n";
    leaderKeyFile << "    p1    "    << LeaderKeys["p1"]    << "\n";
    leaderKeyFile << "    p2    "    << LeaderKeys["p2"]    << "\n";
    leaderKeyFile << "    e     "     << LeaderKeys["e"]     << "\n";
    leaderKeyFile << "    d     "     << LeaderKeys["d"]     << "\n}";
    leaderKeyFile.close();
    std::cout << "[GDSNode::GDSCrypto] Keys saved at <" + leaderKeysPath + ">\n";
}



std::map<std::string, cpp_int> GDSNode::GDSCrypto::GenerateLeaderKeys()
{
    // p = 2 * q + 1;


    // q = (p - 1) / 2   - it should be ALWAYS 2, either way it is not strengthen enough cause k have a factorizations

    // generate_prime(msb)
    // generate_prime_in_range(in, to)

    // we can generate p, then look for (p - 1) / 2 value is prime? if its prime were good.

    uint16_t keySize = 512; //1024 is fucking impossible, one keypair in 30 minutes by 20 threads
    // got second after roughly an hour

    // cpp_int p;
    // cpp_int q;
    // do
    // {
    //     p = generate_prime(keySize);
    //     q = (p - 1) / 2;
    // } while ( q < 547 or !miller_rabin_test(q) );
    //
    // std::cout << "[GDSNodeCrypto] Generated keys:\n p: " << p  << "\nq: " << q << "\n";

    //or

    cpp_int p;
    cpp_int q;
    do
    {
        q = generate_prime(keySize);
        p = 2 * q + 1;
    } while ( (q < 547)  or  !miller_rabin_test(p) );

    std::cout << "[GDSNodeCrypto] Generated keys:\np: " << p  << "\nq: " << q << "\n";

    cpp_int prime = ELGAMAL::findPrimitive(p);
    cpp_int alpha = fast_exp_mod(prime, (p-1)/q, p);
    
    //z [1, q-1]      L = alpha^z_inv (mod p)
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> z_dist(1, q-1);
    cpp_int z = z_dist(gen);
    //cpp_int z_inv = std::get<1>(extended_euclidean_alg(z, q)); // no fucnking way
    // (z_inv < 0) { z_inv += q; }
    cpp_int L = fast_exp_mod(alpha, z, p); //aga


    //n, e, d, p1, p2
    cpp_int p1 = generate_prime(256);
    cpp_int p2;
    do {
        p2 = generate_prime(256);
    } while (p1 == p2);
    cpp_int n = p1*p2;

    cpp_int phi = (p1 - 1) * (p2 - 1);
    cpp_int e = 65537; //overwrite (stable)
    cpp_int d = std::get<1>(extended_euclidean_alg(e, phi));
    if (d <= 0) d+= phi;
    if ((e * d) % phi != 1) {
        std::cout << "Invalid private key: (e * d) % phi != 1\n";
        throw std::invalid_argument("Invalid private key");
    }

    //что я забыл?? хз
    std::map<std::string, cpp_int> result;
    result["p"] = p;
    result["q"] = q;
    result["alpha"] = alpha;

    result["z"] = z;
    result["L"] = L;

    result["n"] = n;
    result["p1"] = p1;
    result["p2"] = p2;
    result["e"] = e;
    result["d"] = d;

    return result;
}