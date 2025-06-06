#pragma once

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
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
#include <bitset>
#include <boost/algorithm/string.hpp>

using namespace boost::multiprecision;

typedef boost::multiprecision::cpp_dec_float_100 bf;

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
    galois_field(cpp_int p, cpp_int k, std::vector<cpp_int> irreducible)
    : p(p), k(k), irreducible(std::move(irreducible)) {}

    std::vector<cpp_int> product(const std::vector<cpp_int>& first, const std::vector<cpp_int>& second);
    std::vector<cpp_int> sum(const std::vector<cpp_int>& first, const std::vector<cpp_int>& second);
    void print();

private:
    cpp_int p;
    cpp_int k;
    std::vector<cpp_int> irreducible;
    std::vector<cpp_int> reduction(const std::vector<cpp_int>& poly);
};


cpp_int fast_exp(cpp_int base, cpp_int exponent);
cpp_int fast_exp_mod(cpp_int base, cpp_int exponent, cpp_int modulus);
std::tuple<cpp_int, cpp_int, cpp_int> extended_euclidean_alg(cpp_int x, cpp_int y);
cpp_int jacobi(cpp_int a, cpp_int p);                                          
bool fermat_test(cpp_int n);
bool solovay_strassen_test(cpp_int n);
bool miller_rabin_test(cpp_int n);
std::string ferma(const cpp_int& number);
cpp_int generate_prime(uint64_t k);
cpp_int generate_prime_in_range(cpp_int from, cpp_int to);
std::vector<cpp_int> solve_1d_congruence(cpp_int a, cpp_int b, cpp_int p);
std::tuple<cpp_int, cpp_int> solve_2d_congruence(cpp_int a, cpp_int p);
cpp_int solve_1d_congruence_system(const std::vector<cpp_int>& remainders, const std::vector<cpp_int>& moduli);
void printPolynomial(const std::vector<cpp_int>& poly);
cpp_int pollard_method(cpp_int n);
cpp_int pollard_p1_method(cpp_int n);
std::vector<cpp_int> find_divisors_sqrt(cpp_int n);
std::vector<cpp_int>  pollard_p_method(cpp_int p, cpp_int a, cpp_int b);
cpp_int find_r(cpp_int a, cpp_int p);
std::vector<std::tuple<cpp_int, cpp_int, cpp_int>> file_read(const std::string& filename);
void pollard_method_file_tests(std::string filename);
std::string to_hex(cpp_int num);
cpp_int mod_inverse(cpp_int a, cpp_int m);


std::vector<uint8_t> PKCS7_Padding(const std::vector<uint8_t>& data, size_t block_size);
std::vector<uint8_t> PKCS7_Unpadding(const std::vector<uint8_t>& data);
std::string BytesToText(const std::vector<uint8_t>& bytes);
std::vector<cpp_int> ChunkMessage(const std::vector<uint8_t>& bytes, size_t block_size);
std::vector<uint8_t> UnchunkMessage(const std::vector<cpp_int>& chunks, size_t block_size);
std::map<std::string, cpp_int> ReadKey(const std::string& KeyFile);

// Utility function to convert string to hex
inline std::string stringToHex(const std::string& input) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : input) {
        oss << std::setw(2) << static_cast<int>(c);
    }
    return oss.str();
}


std::vector<uint8_t> TextToBytes(const std::string& text);
std::vector<uint8_t> reverseBytes(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> UINT128ToBytes(uint128_t num);
std::vector<uint8_t> UINT64ToBytes(uint64_t num);

std::string concateUINT32Hexes(uint32_t value);
std::string concateUINT64Hexes(uint64_t value);

template <typename T>
T bytesToUINT(std::vector<uint8_t> data)
{
    T result = 0;
    int temp = 0;
    if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, uint16_t> || std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t>)
    {
        if constexpr (std::is_same_v<T, uint8_t>) {
            printf("[Warn][alghoritms.h/bytesToUINT] Type uint8_t to uint8_t, set first byte as \\0x%x\n", data[0]);
            return data[0];
        }
        if (data.size() > sizeof(T)) {
            printf("[Warn][alghoritms.h/bytesToUINT] Chosen type (STD) cannot contain the whole array, it will cut down\n");
        }
        if (data.size() < sizeof(T)) {
                printf("[Warn][alghoritms.h/bytesToUINT] Array size is smaller than expected, filling it with zeroes\n");
                data.insert(data.begin(), (sizeof(T) - size(data)), 0x00);
            }
        } else
        {
            //std::cout << sizeof(T) << " dt: " << data.size() << std::endl;

            // for (auto i : data)
            // {
            //     std::cout << i << " ";
            // }
            //std::cout << "\n\n";
            temp = 8;
            if (data.size() > (sizeof(T) - 8)) {
                printf("[Warn][alghoritms.h/bytesToUINT] Chosen type (BOOST) cannot contain the whole array, array will cut down\n");
            }
        if (data.size() < (sizeof(T) - 8)) {
            printf("[Warn][alghoritms.h/bytesToUINT] Array size is smaller than expected, filling it with zeroes\n");
            data.insert(data.begin(), ((sizeof(T) - 8) - size(data)), 0x00);
        }
    }

    //std::cout << sizeof(T) - 1 - temp << std::endl;
    for (int i = 0; i < (sizeof(T) - temp); i++) {
        result |= static_cast<T>(data[(sizeof(T) - 1 - temp - i)]) << (i * 8);
    }
    return result;
}


template <typename T>
std::vector<uint8_t> UINTToBytes(T num)
{
    if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, uint16_t> || std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t>)
    {
        std::vector<uint8_t> bytes;
        for (int i = 0; i < (sizeof(num)); i++) {
            uint8_t byte = static_cast<uint8_t>((num >> (((sizeof(num)) - 1 - i) * 8)) & 0xFF);
            bytes.push_back(byte);
        }
        return bytes;
    } else
    {
        std::vector<uint8_t> bytes;
        for (int i = 8; i < (sizeof(num)); i++) {
            uint8_t byte = static_cast<uint8_t>((num >> (((sizeof(num)) - 1 - i) * 8)) & 0xFF);
            bytes.push_back(byte);
        }
        return bytes;
    }
}


std::string toHexString(uint512_t number);

std::vector<uint8_t> hexStringToBytes(const std::string& hex);

std::vector<uint8_t> stringToBytes(std::string data);

std::string BytesToHexString(const std::vector<uint8_t>& bytes);