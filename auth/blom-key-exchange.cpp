#include "auth-client.hpp"
#include "auth-server.hpp"
#include "auth-tsa-server.hpp"
#include <boost/numeric/ublas/matrix.hpp> 
#include <boost/numeric/ublas/io.hpp>

using boost::numeric::ublas::matrix;

#define ALICE_PORT 8000
#define BOB_PORT 8001
#define TSA_PORT 8002

// TSA utility functions
void GenerateSecretMatrix(matrix<cpp_int>& Matrix, cpp_int p, size_t k);
void GeneratePublicVector(matrix<cpp_int>& Matrix, cpp_int p, size_t k);
matrix<cpp_int> matrix_mod(const matrix<cpp_int>& m, const cpp_int& p);
//


void AuthClient::BlomSequence() {
    // TSA
    std::string received = ListenAndReceive(ALICE_PORT);
    ptree data;
    std::stringstream ss(received);
    read_json(ss, data);
    //endof TSA
    
    size_t k = 10;
    matrix<cpp_int> r_Alice(k, 1), a_Alice(k, 1);
    cpp_int p = data.get<cpp_int>("p");
    for (size_t i = 0; i < k; ++i) {
        r_Alice(i, 0) = data.get<cpp_int>("r_Alice." + std::to_string(i));
        a_Alice(i, 0) = data.get<cpp_int>("a_Alice." + std::to_string(i));
    }

    // r_Alice -> Bob
    ptree r_Alice_data;
    for (size_t i = 0; i < k; ++i) {
        r_Alice_data.add("r_Alice." + std::to_string(i), r_Alice(i, 0));
    }
    std::stringstream ss_r_Alice;
    write_json(ss_r_Alice, r_Alice_data);
    SendMsg(BOB_PORT, ss_r_Alice.str());

    // Alice <- r_Bob 
    std::string bob_data = ListenAndReceive(ALICE_PORT);
    ptree bob_ptree;
    std::stringstream bob_ss(bob_data);
    read_json(bob_ss, bob_ptree);
    matrix<cpp_int> r_Bob(k, 1);
    for (size_t i = 0; i < k; ++i) {
        r_Bob(i, 0) = bob_ptree.get<cpp_int>("r_Bob." + std::to_string(i));
    }

    matrix<cpp_int> key = matrix_mod(prod(trans(a_Alice), r_Bob), p);
    std::cout << "[AuthServer] Session key: " << std::hex << key(0, 0) << "\n\n";
}

void AuthServer::BlomSequence() {

    // TSA
    std::string received = ListenAndReceive(BOB_PORT);
    ptree data;
    std::stringstream ss(received);
    read_json(ss, data);

    size_t k = 10;
    matrix<cpp_int> r_Bob(k, 1), a_Bob(k, 1);
    cpp_int p = data.get<cpp_int>("p");
    for (size_t i = 0; i < k; ++i) {
        r_Bob(i, 0) = data.get<cpp_int>("r_Bob." + std::to_string(i));
        a_Bob(i, 0) = data.get<cpp_int>("a_Bob." + std::to_string(i));
    }

    // Bob <- r_Alice
    std::string alice_data = ListenAndReceive(BOB_PORT);
    ptree alice_ptree;
    std::stringstream alice_ss(alice_data);
    read_json(alice_ss, alice_ptree);
    matrix<cpp_int> r_Alice(k, 1);
    for (size_t i = 0; i < k; ++i) {
        r_Alice(i, 0) = alice_ptree.get<cpp_int>("r_Alice." + std::to_string(i));
    }

    // r_Bob -> Alice
    ptree r_Bob_data;
    for (size_t i = 0; i < k; ++i) {
        r_Bob_data.add("r_Bob." + std::to_string(i), r_Bob(i, 0));
    }
    std::stringstream ss_r_Bob;
    write_json(ss_r_Bob, r_Bob_data);
    SendMsg(ALICE_PORT, ss_r_Bob.str());

    //skey
    matrix<cpp_int> key = matrix_mod(prod(trans(a_Bob), r_Alice), p);
    std::cout << "[AuthServer] Session key: " << std::hex << key(0, 0) << "\n\n";
}
    
void AuthTSA::BlomSequence()
{
    std::cout << "[AuthTSA] Generating params... \n";

    cpp_int p = generate_prime(512);
    size_t k = 10;

    matrix<cpp_int> D(k, k); GenerateSecretMatrix(D, p, k);
    matrix<cpp_int> r_Alice(k, 1); GeneratePublicVector(r_Alice, p, k);
    matrix<cpp_int> r_Bob(k, 1); GeneratePublicVector(r_Bob, p, k);

    // Private vectors
    matrix<cpp_int> a_Alice = matrix_mod(prod(D, r_Alice), p);
    matrix<cpp_int> a_Bob = matrix_mod(prod(D, r_Bob), p);

    // ptree >> ss >> string
    ptree AliceData, BobData;
    for (size_t i = 0; i < k; ++i) {
        AliceData.add("r_Alice." + std::to_string(i), r_Alice(i, 0));
        AliceData.add("a_Alice." + std::to_string(i), a_Alice(i, 0));
        BobData.add("r_Bob." + std::to_string(i), r_Bob(i, 0));
        BobData.add("a_Bob." + std::to_string(i), a_Bob(i, 0));
    }
    AliceData.put("p", p);
    BobData.put("p", p);
    
    std::stringstream ss_Alice, ss_Bob;
    write_json(ss_Alice, AliceData);
    write_json(ss_Bob, BobData);
    std::cout << "[AuthTSA] Alice: " << ss_Alice.str() << "\n[AuthTSA] Bob: " << ss_Bob.str() << "\n";
    SendMsg(ALICE_PORT, ss_Alice.str());
    SendMsg(BOB_PORT, ss_Bob.str());

    std::cout << "[AuthTSA] Blom parameters sent to Alice and Bob" << std::endl;
    
}


matrix<cpp_int> matrix_mod(const matrix<cpp_int>& m, const cpp_int& p) {
    matrix<cpp_int> result(m.size1(), m.size2());
    for (size_t i = 0; i < m.size1(); ++i) {
        for (size_t j = 0; j < m.size2(); ++j) {
            result(i, j) = m(i, j) % p;
        }
    }
    return result;
}


void GeneratePublicVector(matrix<cpp_int>& Matrix, cpp_int p, size_t k)
{
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(1, p - 1);
    for (size_t i = 0; i < k; ++i) {
        Matrix(i, 0) = dist(gen);
    }
}


void GenerateSecretMatrix(matrix<cpp_int>& Matrix, cpp_int p, size_t k)
{
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(1, p - 1);
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = i; j < k; ++j) {
            cpp_int x = dist(gen);
            Matrix(i, j) = x;
            Matrix(j, i) = x;
        }
    }
}