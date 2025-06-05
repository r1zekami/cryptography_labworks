#include "alghoritms.h"


bi fast_exp(bi base, bi exponent) {
    bi result = 1;

    while (exponent > 0) {
        if (exponent & 1) {
            result *= base;
        }
        base *= base;       
        exponent >>= 1;
    }
    
    return result;
}


bi fast_exp_mod(bi base, bi exponent, bi modulus) {
    if (modulus <= 0) {
        throw std::invalid_argument("Modulus must be positive");
    }
    base = (base % modulus + modulus) % modulus;

    if (exponent < 0) {
        bi inv = mod_inverse(base, modulus);
        if (inv == -1) {
            std::cout << "[algorithms.cpp/fast_exp_mod] [ERR] Inverse does not exist\n";
            throw std::runtime_error("Inverse does not exist");
        }
        base = inv;
        exponent = -exponent;
    }

    bi result = 1;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}


std::tuple<bi, bi, bi> extended_euclidean_alg(bi x, bi y) {

    // x < 0 ? x*=(-1) : x;
    // y < 0 ? y*=(-1) : y;

    bi old_x{x}, old_y{y};
    bi a1{0}, b1{1};
    bi a2{1}, b2{0};
    bi q, r, a, b;
    
    while (y != 0) {
        q = x / y;
        r = x - q * y;
        
        a = a2 - q * a1; 
        b = b2 - q * b1;

        x = y;  
        y = r;
        
        a2 = a1; a1 = a;
        b2 = b1; b1 = b;
    }

    a = a2; b = b2;
    return {x, a, b};
}



bi jacobi(bi a, bi p)
{
    if (p <= 0 || p % 2 == 0) {
        printf("Error: p должно быть положительным нечетным числом");
        return -10;
    }
    bi result{1};

    if (a == 0) { return 0; }   // 0 = 0 mod p
    if (a == 1) { return result; }  // 1^2 = 1 mod p

    
    bi k = 0; 
    bi b = a;

    while (b % 2 == 0)
    {
        b /= 2;
        k += 1;
    }
    // a = b * 2^k
    
    bi sign = 1;
    if (k % 2 != 0)
    {
        if (p % 8 == 1 || p % 8 == 7) {
            sign = 1;
        }
        else if (p % 8 == 3 || p % 8 == 5) {
            sign = -1;
        }
    }

    if (b == 1) {
        return result * sign;
    }

    if (b % 4 == 3 && p % 4 == 3) //закон кв взаимности
    {
        sign = -sign;
    }

    return result * sign * jacobi(p % b, b); //(a/p) = (p mod a / a)
}


//uniform int distribuiton
bool fermat_test(bi n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;

    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<bi> dist(2, n - 2);

    for (int i = 0; i <= 5; i++) {
        if (fast_exp_mod(dist(gen), n-1, n) != 1) {
            return false;
        }
    }
    return true;
}


std::string ferma(const bi& number) {
    bool isPrime = fermat_test(number);
    return isPrime ? "Number " + number.str() + " is probably prime" 
                   : "Number " + number.str() + " is composite";
}


bool solovay_strassen_test(bi n)
{
    if (n <= 1 or n == 4)
        return false;
    if (n <= 3)
        return true;

    boost::random::mt19937 gen(static_cast<unsigned int>(std::random_device{}()));

    for (int i = 0; i <= 5; i++)
    {
        boost::random::uniform_int_distribution<bi> dist(2, n - 2);

        bi a = dist(gen);
        bi r = fast_exp_mod(a, (n - 1) / 2, n);

        if (r != 1 and r != n-1)
        {
            return false;
        }

        bi s = jacobi(a, n);
        if (s < 0) s += n; 

        if (r % n != s % n) {
            return false;
        }
    }
    return true;
}



bool miller_rabin_test(bi n)
{
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    bi s = 0;
    bi d = n - 1;

    while (d % 2 == 0) {
        d /= 2;
        s++;
    }

    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<bi> dist(2, n - 2);

    for (int i = 0; i < 20; ++i) {
        bi a = dist(gen);
        bi x = fast_exp_mod(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool is_witness = false;
        for (bi r = 1; r < s; ++r) {
            x = (x * x) % n;
            if (x == n - 1) {
                is_witness = true;
                break;
            }
        }

        if (!is_witness) return false;
    }
    return true;
}


bi generate_prime(uint64_t k) {
    if (k <= 1) return 2;
    
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<bi> dist((fast_exp(2,k) - 1), fast_exp(2, k+1) - 1);
    bi p(0);
    while (true) {
        p = dist(gen);
        p |= 0x1;

        if (p == 2) return 2;
        
        if (p % 3 == 0 || p % 5 == 0 || p % 7 == 0) {
            if (p == 3 or p == 5 or p == 7) return true;
        }
        
        if (miller_rabin_test(p))
        {
            //std::cout << msb(p) << std::endl;
            return p;
        }
    }
}


bi generate_prime_in_range(cpp_int from, cpp_int to) {
    if (from > to) std::swap(from, to);
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<bi> dist(from, to);
    bi p(0);
    while (true) {
        p = dist(gen);
        p |= 0x1;

        if (p == 2) return 2;
        
        if (p % 3 == 0 || p % 5 == 0 || p % 7 == 0) {
            if (p == 3 or p == 5 or p == 7) return true;
        }
        
        if (miller_rabin_test(p))
        {
            //std::cout << msb(p) << std::endl;
            return p;
        }
    }
}



std::vector<bi> solve_1d_congruence(bi a, bi b, bi p) {
    std::vector<bi> solutions;

    auto [d, x, y] = extended_euclidean_alg(a, p);

    if (b % d != 0) {
        std::cout << "No solutions exist" << std::endl;
        return solutions;
    }

    bi b1 = b / d;
    bi p1 = p / d;
    bi x0 = ((x * b1) % p1 + p1) % p1;

    for (bi i = 0; i < d; ++i) {
        solutions.push_back((x0 + i * p1) % p);
    }

    return solutions;
}


std::tuple<bi, bi> solve_2d_congruence(bi a, bi p) {
    if (jacobi(a, p) != 1) {
        std::cout << "lejandr != 1, no solutions exist" << std::endl;
        return std::make_tuple(0, 0);
    }

    // Представляем p в виде p = 2^k * h + 1
    bi k = 0;
    bi h = p - 1;
    while (h % 2 == 0) {
        k++;
        h /= 2;
    }

    bi a1 = fast_exp_mod(a, (h + 1) / 2, p);
    bi a2 = fast_exp_mod(a, p - 2, p); // a^{-1} mod p

    bi N = 2;
    while (jacobi(N, p) != -1) {
        N++;
    }

    bi N1 = fast_exp_mod(N, h, p);
    bi N2 = 1;
    bi j = 0;

    for (bi i = 0; i < k - 1; ++i) {
        bi b = (a1 * N2) % p;
        bi c = (a2 * b * b) % p;
        bi exponent = fast_exp(2, k - 2 - i);
        bi d = fast_exp_mod(c, exponent, p);

        if (d == 1) {
            j = 0;
        } else if (d == p - 1) {
            j = 1;
        }

        N2 = (N2 * fast_exp_mod(N1, fast_exp(2, j), p)) % p;
    }

    bi x1 = (a1 * N2) % p;
    bi x2 = p - x1;
    return std::make_tuple(x1, x2);
}


bi solve_1d_congruence_system(const std::vector<bi>& remainders, const std::vector<bi>& moduli)
{
    int n = remainders.size();
    bi M = 1;
    for (int i = 0; i < n; i++) {
        M *= moduli[i];
    }

    bi result = 0;
    for (int i = 0; i < n; i++) {
        bi Mi = M / moduli[i];
        
        auto [gcd, x, y] = extended_euclidean_alg(Mi, moduli[i]);
        if (gcd != 1) {
            std::cout << "Modules is not coprime\n";
            return -1;
        }
        bi yi = (x % moduli[i] + moduli[i]) % moduli[i];
        
        result += remainders[i] * Mi * yi;
    }

    return result % M;
}


void printPolynomial(const std::vector<bi>& poly) {
    bool first_term = true;

    for (int i = poly.size() - 1; i >= 0; i--) {
        bi coeff = poly[i];
        if (coeff == 0) continue;

        if (!first_term) {
            printf(" + ");
        } else {
            first_term = false;
        }

        if (coeff != 1 || i == 0) {
            std::cout << coeff;
        }

        if (i > 0) {
            printf("x");
            if (i > 1) {
                std::cout << "^" << i;
            }
        }
    }

    if (first_term) { printf("0"); }
    printf("\n");
}

cpp_int mod_inverse(cpp_int a, cpp_int m) {
    return std::get<1>(extended_euclidean_alg(a, m));
}

std::vector<bi> galois_field::reduction(const std::vector<bi>& poly) {
    if (poly.size() < irreducible.size()) {
        return poly;
    }

    std::vector<bi> result = poly;

    while (result.size() >= irreducible.size()) {
        bi coefficient = result.back();

        if (coefficient == 0) {
            result.pop_back();
            continue;
        }

        auto [gcd, x, y] = extended_euclidean_alg(coefficient, p);

        if (gcd != 1) {
            printf("No inverse, GCD != 1");
            return {};
        }

        bi inv = (x % p + p) % p;

        for (size_t i = 0; i < result.size(); ++i) {
            result[i] = (result[i] * inv) % p;
        }

        size_t shift = result.size() - irreducible.size();
        for (size_t i = 0; i < irreducible.size(); ++i) {
            result[shift + i] = (result[shift + i] + irreducible[i]) % p;
        }

        result.pop_back();
    }

    while (!result.empty() && result.back() == 0) { result.pop_back(); } //дроп нулквыы\х
    return result.empty() ? std::vector<bi>{0} : result;
}


std::vector<bi> galois_field::product(const std::vector<bi>& first, const std::vector<bi>& second) {
    std::vector<bi> result(first.size() + second.size() - 1, 0);
    for (size_t i = 0; i < first.size(); ++i) {
        for (size_t j = 0; j < second.size(); ++j) {
            result[i + j] += first[i] * second[j];
            result[i + j] %= p;
        }
    }
    return reduction(result);
}


std::vector<bi> galois_field::sum(const std::vector<bi>& first, const std::vector<bi>& second) {
    size_t max_size = std::max(first.size(), second.size());
    std::vector<bi> result(max_size, 0);

for (size_t i = 0; i < max_size; ++i) {
        bi a = (i < first.size()) ? first[i] : 0;
        bi b = (i < second.size()) ? second[i] : 0;
        result[i] = (a + b) % p;
    }

    result = reduction(result);
    
    if (result.empty()) {
        return {0};
    }

    return result;
}


void galois_field::print() {
    std::cout << "Galois Field GF(" << p << "^" << k << ") with irreducible polynomial: ";
    printPolynomial(irreducible);
    printf("\n");
}


bi pollard_method(bi n) {

    auto f = [n](bi x) {
        return (x * x + 1) % n;
    };

    for (int attempts = 0; attempts < 10; ++attempts)
    {
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<bi> dist(2, n - 1);
        bi c = dist(gen);
        bi a = c;
        bi b = c;
        
        while (true) {
            a = f(a);
            b = f(f(b));
            bi d = std::get<0>(extended_euclidean_alg(a - b, n));

            if (1 < d && d < n) {
                return d;
            } else if (d == n) {
                break;
            }
        }
    }
    return 0;
}


bi pollard_p1_method(bi n)
{
    bi p;
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<bi> dist(2, n - 2);
    
    bi a = dist(gen);
    bi d = std::get<0>(extended_euclidean_alg(a, n));

    if (d >= 2) {p = d; return p;}

    for (auto i : PRIMES)
    {
        bi l = static_cast<bi>(std::log(n.convert_to<double>()) / std::log(i));
        
        a = fast_exp_mod(a, fast_exp(i, l), n);

        d = std::get<0>(extended_euclidean_alg(a - 1, n));

        if (d >= 2 and d < n) return d;
        if (d == n) break;
    }
    return 1;
}


std::vector<cpp_int> find_divisors_sqrt(cpp_int n) {
    std::vector<cpp_int> divisors;
    for (cpp_int i = 1; i <= sqrt(n); i++) {
        if (n % i == 0) {
            divisors.push_back(i);
            if (i != n / i) {
                divisors.push_back(n / i);
            }
        }
    }
    return divisors;
}


bi find_r(bi a, bi p)
{
    if (std::get<0>(extended_euclidean_alg(a, p)) != 1) {
        if (!miller_rabin_test(p)) {
            printf("gcd(a, p) != 1\n");
            return -1;
        }
    }
    
    bi phi_p = p - 1;
    std::vector<bi> divisors = find_divisors_sqrt(phi_p);

    for (auto d : divisors) {
        if (fast_exp_mod(a, d, p) == 1) {
            return d;
        }
    }
    return -1;
}


std::vector<bi> pollard_p_method(bi p, bi a, bi b)
{
    if (!miller_rabin_test(p)) {
        printf("P is not prime\n");
        return {-1};
    }

    bi r = find_r(a, p);
    if (r == -1)
    {
        printf("Cannot find valid r\n");
        return {-1};
    }

    if (b <= 1 or b >= p)
    {
        printf("b should be 1 < b < p\n");
        return {-1};
    }
    
    // c = (a^v)*(b^v) (mod p)
    bi c = fast_exp_mod(a, 2, p) * fast_exp_mod(b, 2, p) % p;
    bi d = c;
    
    auto f = [p, a, b](bi c, bi& u, bi& v) {
        if (c < p / 2) {
            c = (a * c) % p;
            u = (u + 1);
        } else {
            c = (b * c) % p;
            v = (v + 1);
        }
        return c;
    };

    bi u_c = 2, v_c = 2;
    bi u_d = 2, v_d = 2; 

    uint16_t steps = 0;
    while (true) {
        if (steps++ > 10000)
        {
            std::cout << "Steps limit has exceed 10000\n";
            return {-1};
        }
        c = f(c, u_c, v_c);

        d = f(d, u_d, v_d);
        d = f(d, u_d, v_d);

        if (c == d) {
            break;
        }
    }

    std::vector<bi> solutions = solve_1d_congruence((v_c - v_d + r) % r, (u_d - u_c + r) % r, r);

    if (solutions.empty()) {
        printf("Решений нет\n");
        return {0};
    }

    return solutions;
}


std::vector<std::tuple<bi, bi, bi>> file_read(const std::string& filename) {
    std::vector<std::tuple<bi, bi, bi>> coefficients;
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "File error" << filename << '\n';
        return coefficients;
    }

    bi p, a, b;
    while (file >> p >> a >> b) {
        coefficients.push_back(std::make_tuple(p, a, b));
    }

    file.close();
    return coefficients;
}


void pollard_method_file_tests(std::string filename)
{
    std::vector<std::tuple<bi, bi, bi>> coefficients = file_read(filename);

    if (coefficients.empty()) {
        std::cerr << "File empty or cannot be read.\n";
        return;
    }

    for (const auto& tuple : coefficients) {
        bi p = std::get<0>(tuple);
        bi a = std::get<1>(tuple);
        bi b = std::get<2>(tuple);

        std::cout << "("<< p << ", " << a << ", " << b << ") : ";

        for (auto solution : pollard_p_method(p, a, b))
        {
            std::cout << solution << " ";
        }
        printf("\n");
    }
}

std::string to_hex(cpp_int num) 
{
    std::stringstream ss;
    ss << std::hex << num;
    return ss.str();
}


//  Padding & Blocks logic for cipher-systems --------------------------------------------------------------------------


std::vector<uint8_t> PKCS7_Padding(const std::vector<uint8_t>& data, size_t block_size) {
    std::vector<uint8_t> padded_data = data;
    size_t padding_length = block_size - (data.size() % block_size);
    padded_data.insert(padded_data.end(), padding_length, static_cast<uint8_t>(padding_length));
    return padded_data;
}

        
std::vector<uint8_t> PKCS7_Unpadding(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;
    uint8_t padding_length = data.back();
    
    if (padding_length == 0 || padding_length > data.size()) {
        return data;
    }
    
    for (size_t i = data.size() - padding_length; i < data.size(); ++i) {
        if (data[i] != padding_length) {
            return data;
        }
    }
    
    return std::vector<uint8_t>(data.begin(), data.end() - padding_length);
}


std::vector<bi> ChunkMessage(const std::vector<uint8_t>& bytes, size_t block_size) {
    std::vector<bi> chunks;
    size_t num_blocks = (bytes.size() + block_size - 1) / block_size;

    for (size_t i = 0; i < num_blocks; ++i) {
        bi chunk = 0;
        for (size_t j = 0; j < block_size; ++j) {
            size_t index = i * block_size + j;
            if (index < bytes.size()) {
                chunk = (chunk << 8) | bytes[index];
            } else {
                chunk = (chunk << 8);
            }
        }
        chunks.push_back(chunk);
    }

    return chunks;
}


std::vector<uint8_t> UnchunkMessage(const std::vector<bi>& chunks, size_t block_size) {
    std::vector<uint8_t> bytes;

    for (const bi& chunk : chunks) {
        for (size_t i = 0; i < block_size; ++i) {
            uint8_t byte = static_cast<uint8_t>((chunk >> (8 * (block_size - 1 - i))) & 0xFF);
            bytes.push_back(byte);
        }
    }

    return bytes;
}


std::vector<uint8_t> TextToBytes(const std::string& text) {
    std::vector<uint8_t> bytes;
    for (char c : text) {
        bytes.push_back(static_cast<uint8_t>(c));
    }
    return bytes;
}

    
std::string BytesToText(const std::vector<uint8_t>& bytes) {
    std::string text;
    for (uint8_t byte : bytes) {
        text.push_back(static_cast<char>(byte));
    }
    return text;
}


std::map<std::string, bi> ReadKey(const std::string& KeyFile) {
    std::ifstream file(KeyFile);
    if (!file.is_open()) {
        std::cout << ("Failed to open public key file: " + KeyFile + "\n");
    }

    std::map<std::string, bi> Key;
    std::string line;
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string keyName;
        std::string value;
        ss >> keyName >> value;

        if (keyName.find("}") != std::string::npos) {
            break;
        }

        Key[keyName] = bi(value);
    }

    file.close();
    return Key;
}



//
//----------------------------------------------------------------------------------------------------------------------
//------------------------------------------------utilities-------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
//


std::vector<uint8_t> reverseBytes(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> result = bytes;
    std::reverse(result.begin(), result.end());
    return result;
}

std::vector<uint8_t> UINT128ToBytes(uint128_t num)
{
    std::vector<uint8_t> bytes;
    for (int i = 0; i < 16; i++) {
        uint8_t byte = static_cast<uint8_t>((num >> ((15 - i) * 8)) & 0xFF);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> UINT64ToBytes(uint64_t num)
{
    std::vector<uint8_t> bytes;
    for (int i = 0; i < 8; i++) {
        uint8_t byte = static_cast<uint8_t>((num >> ((7 - i) * 8)) & 0xFF);
        bytes.push_back(byte);
    }
    return bytes;
}


std::string concateUINT64Hexes(uint64_t value)
{
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << value;
    return ss.str();
}

std::string concateUINT32Hexes(uint32_t value)
{
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << value;
    return ss.str();
}


std::string toHexString(uint512_t number) {
    std::stringstream ss;
    ss << "0x" << std::hex << number;
    return ss.str();
}

std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    if (hex.substr(0, 2) != "0x") {
        throw std::invalid_argument("Hex string must start with '0x'");
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 2; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}


std::vector<uint8_t> stringToBytes(std::string data)
{
    return std::vector<uint8_t>(data.begin(), data.end());
}


std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << "0x";
    for (const auto& byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

