#pragma once

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <vector>
#include <tuple>
#include <random>
#include <iostream>
#include <set>
#include <fstream>
#include <map>

using namespace boost::multiprecision;

typedef boost::multiprecision::cpp_dec_float_100 bf;
typedef boost::multiprecision::cpp_int bi;

inline std::vector<int> PRIMES = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
                           97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
                           193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
                           307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
                           421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
                           547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653,
                           659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                           797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919,
                           929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997};

class galois_field
{
public:
    galois_field(bi p, bi k, std::vector<bi> irreducible)
    : p(p), k(k), irreducible(std::move(irreducible)) {}

    std::vector<bi> product(const std::vector<bi>& first, const std::vector<bi>& second);
    std::vector<bi> sum(const std::vector<bi>& first, const std::vector<bi>& second);
    void print();

private:
    bi p;
    bi k;
    std::vector<bi> irreducible;
    std::vector<bi> reduction(const std::vector<bi>& poly);
};


bi fast_exp(bi base, bi exponent);
bi fast_exp_mod(bi base, bi exponent, bi modulus);
std::tuple<bi, bi, bi> extended_euclidean_alg(bi x, bi y);
bi jacobi(bi a, bi p);                                          
bool fermat_test(bi n);
bool solovay_strassen_test(bi n);
bool miller_rabin_test(bi n);
std::string ferma(const bi& number);
bi generate_prime(uint64_t k);
std::vector<bi> solve_1d_congruence(bi a, bi b, bi p);
std::tuple<bi, bi> solve_2d_congruence(bi a, bi p);
bi solve_1d_congruence_system(const std::vector<bi>& remainders, const std::vector<bi>& moduli);
void printPolynomial(const std::vector<bi>& poly);

bi pollard_method(bi n);
bi pollard_p1_method(bi n);

std::vector<cpp_int> find_divisors_sqrt(cpp_int n);
std::vector<bi>  pollard_p_method(bi p, bi a, bi b);
bi find_r(bi a, bi p);
std::vector<std::tuple<bi, bi, bi>> file_read(const std::string& filename);
void pollard_method_file_tests(std::string filename);



std::vector<uint8_t> PKCS7_Padding(const std::vector<uint8_t>& data, size_t block_size);
std::vector<uint8_t> PKCS7_Unpadding(const std::vector<uint8_t>& data);

std::vector<uint8_t> TextToBytes(const std::string& text);
std::string BytesToText(const std::vector<uint8_t>& bytes);

std::vector<bi> ChunkMessage(const std::vector<uint8_t>& bytes, size_t block_size);
std::vector<uint8_t> UnchunkMessage(const std::vector<bi>& chunks, size_t block_size);

std::map<std::string, bi> ReadKey(const std::string& KeyFile);
