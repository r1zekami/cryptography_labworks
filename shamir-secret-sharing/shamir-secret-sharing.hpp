#pragma once
#include "../alghoritms.h"


/* Usage:

    std::string secret = "Hello i am very secret message";
    cpp_int n = 10, k = 3;
    cpp_int p = generate_prime(512);
    auto points = ShamirSecretSharing::SplitSecret(p, secret, n, k);
    std::string Recovered = ShamirSecretSharing::RecoverSecret(p, {points[0], points[1], points[2]});
    std::cout <<  "Recovered: " << Recovered << "\n";

*/



class ShamirSecretSharing
{
public:
    static std::vector<std::pair<cpp_int, cpp_int>> SplitSecret(cpp_int p, std::string Secret, cpp_int N, cpp_int K, const std::string& Filepath = SplittedTextFilepath)
    {
        std::cout << "Secret: " << Secret << "\n";
        cpp_int secretValue = 0;
        for (char c : Secret) {
            secretValue = (secretValue << 8) + static_cast<cpp_int>(c);
        }
        std::cout << "Hexed secret: " << std::hex << secretValue << "\n";

        std::vector<cpp_int> Coefficients;
        Coefficients.push_back(secretValue);
        
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<cpp_int> dist(1, p - 1);
        for (cpp_int i = 0; i < K - 1; ++i) {
            Coefficients.push_back(dist(gen));
        }

        std::cout << "Coefficients: ";
        for (auto a : Coefficients)
        {
            std::cout << a << " ";
        }
        std::cout << "\n";
        
        // Calculate n points of polynomial 
        std::vector<std::pair<cpp_int, cpp_int>> Points;
        for (cpp_int i = 1; i <= N; ++i) {
            cpp_int x = i;
            cpp_int y = 0; //sumof ( coefficients[j] * (x^j) )  <- ai * x^j
            for (size_t j = 0; j < Coefficients.size(); ++j) {
                y = (y + Coefficients[j] * fast_exp_mod(x, j, p)) % p;
            }
            Points.push_back(std::pair(x, y));
            //Points.emplace_back(x, y); ага щас блять
        }

        // aboba
        std::ofstream outFile(Filepath);
        for (const auto& point : Points) {
            outFile << std::dec << point.first << " " << std::hex << point.second << "\n";
        }
        outFile.close();

        return Points;
    }

    static std::string RecoverSecret(cpp_int p, const std::vector<std::pair<cpp_int, cpp_int>>& Points)
    {
        size_t k = Points.size();
        cpp_int secretValue = 0;

        for (size_t i = 0; i < k; ++i) {
            cpp_int xi = Points[i].first;
            cpp_int yi = Points[i].second;
            cpp_int ci = 1;

            for (size_t j = 0; j < k; ++j) {
                if (i != j) {
                    cpp_int xj = Points[j].first;
                    cpp_int numerator = (p - xj) % p; // -xj mod p
                    cpp_int denominator = (xi - xj + p) % p; // x_i - x_j mod p
                    cpp_int denom_inv = mod_inverse(denominator, p); // деление это модульное обратное в поле помним да
                    ci = (ci * numerator % p) * denom_inv % p;
                }
            }
            secretValue = (secretValue + (yi * ci) % p) % p;
        }

        std::string Secret;
        while (secretValue > 0) {
            Secret.insert(Secret.begin(), static_cast<char>(secretValue % 256));
            secretValue >>= 8;
        }

        return Secret;
    }

private:
    constexpr static std::string SplittedTextFilepath = "shamir-secret-sharing/temp/splitted.txt";
};
    