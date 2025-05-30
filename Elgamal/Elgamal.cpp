#include "Elgamal.h"


bi ELGAMAL::findPrimitiveElement(const bi& p) {
    // (bi alpha = 2; alpha < p; ++alpha) или (bi alpha = p - 2; alpha >= 2; --alpha) влияет ли на стойкость?
    for (bi alpha = p - 2; alpha >= 2; --alpha) {
        // Он не совсем примитивный, но в рамках лабы обладает нужными свойствами. (c Кирчик)
        //            a^2 != +-1 mod p
        //            a^((p-1)/2) == 1 mod p
        
        if (fast_exp_mod(alpha, 2, p) == 1 || fast_exp_mod(alpha, 2, p) == p - 1) {
            continue;
        }
        if (fast_exp_mod(alpha, (p - 1) / 2, p) == 1) {
            if (p == alpha) {continue;}
            return alpha;
        }
    }
    return 0;
}


void ELGAMAL::GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize)
{

    bi p = generate_prime(keySize);
    bi a = generate_prime(keySize / 2);
    bi alpha = findPrimitiveElement(p); //ну да но нет
    bi beta = fast_exp_mod(alpha, a, p); // beta = alpha^a mod p

    // std::cout << "p: " << p << "\n";
    // std::cout << "a: " << a << "\n";
    // std::cout << "alpha: " << alpha << "\n";
    // std::cout << "beta: " << beta << "\n";
    
    std::map<std::string, bi> publicKey = {
        {"p", p},
        {"alpha", alpha},
        {"beta", beta}
    };
    std::map<std::string, bi> privateKey = {
        {"p", p},

        {"alpha", alpha},
        {"beta", beta},

        {"a", a}
    };

    WritePublicKey(publicKey, publicKeyFile);
    WritePrivateKey(privateKey, privateKeyFile);
    
}



std::vector<bi> ELGAMAL::Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile)
{
    std::ifstream file(plaintextFile);
    if (!file.is_open()) {
        printf("Failed to open plaintext file");
        return {};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string plaintext = buffer.str();
    file.close();

    auto publicKey = ReadKey(publicKeyFile);
    bi p = publicKey["p"];
    bi alpha = publicKey["alpha"]; // ))
    bi beta = publicKey["beta"];

    // for (auto [key, value] : publicKey) {
    //     std::cout << key << " " << value << "\n";
    // }
    
    std::vector<uint8_t> bytes = TextToBytes(plaintext);
    bytes = PKCS7_Padding(bytes, elgamal_encryption_block_size);
    std::vector<bi> chunks = ChunkMessage(bytes, elgamal_encryption_block_size);
    std::vector<bi> ciphertext;

    for (auto chunk : chunks)
    {
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<bi> dist(0, p - 2);
        bi ephemeral_key = dist(gen);
        bi c1 = fast_exp_mod(alpha, ephemeral_key, p);
        bi c2 = chunk * fast_exp_mod(beta, ephemeral_key, p);

        ciphertext.push_back(c1);
        ciphertext.push_back(c2);
    }

    return ciphertext;
}


std::string ELGAMAL::Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile) {
    auto privateKey = ReadKey(privateKeyFile);
    bi p = privateKey["p"];
    bi a = privateKey["a"];

    std::ifstream file(ciphertextFile);
    if (!file.is_open()) {
        printf("Failed to open ciphertext file");
        return {};
    }

    std::string line;
    std::vector<bi> ciphertext;

    while (std::getline(file, line)) {
        if (line.find("encryptedContent:") != std::string::npos) {
            break;
        }
    }

    while (std::getline(file, line)) {
        if (line.empty() || line.find("}") != std::string::npos) {
            break;
        }

        if (line.substr(0, 2) == "0x") {
            bi number;
            std::istringstream iss(line.substr(2));
            iss >> std::hex >> number;
            ciphertext.push_back(number);
        }
    }

    file.close();

    std::vector<uint8_t> decryptedBytes;

    for (size_t i = 0; i < ciphertext.size(); i += 2)
    {
        bi c1 = ciphertext[i];
        bi c2 = ciphertext[i + 1];
        bi c1_inv = fast_exp_mod(c1, a, p);
        
        c1_inv = std::get<1>(extended_euclidean_alg(c1_inv, p));
        bi m = c2 * c1_inv % p;
        if (m < 0) {m += p;}
        
        std::vector<uint8_t> decryptedMessage = UnchunkMessage({m}, elgamal_encryption_block_size);
        decryptedBytes.insert(decryptedBytes.end(), decryptedMessage.begin(), decryptedMessage.end());
    }
    decryptedBytes = PKCS7_Unpadding(decryptedBytes);
    std::string plaintext = BytesToText(decryptedBytes);
    return plaintext;
}



void ELGAMAL::WritePublicKey(const std::map<std::string, bi>& keyContainer, const std::string& keyFile)
{
    std::ofstream file(keyFile);
    if (!file.is_open()) {
        std::cout << "Failed to open " << keyFile << " for writing." << std::endl;
        return;
    }

    file << "ElgamalPublicKey {\n";
    file << "    p      0x" << std::hex << keyContainer.at("p") << "\n";
    file << "    alpha  0x" << std::hex << keyContainer.at("alpha") << "\n";
    file << "    beta   0x" << std::hex << keyContainer.at("beta") << "\n";
    file << "}\n";

    file.close();
}


void ELGAMAL::WritePrivateKey(const std::map<std::string, bi>& keyContainer, const std::string& keyFile)
{
    std::ofstream file(keyFile);
    if (!file.is_open()) {
        std::cout << "Failed to open " << keyFile << " for writing." << std::endl;
        return;
    }

    file << "ElgamalPrivateKey {\n";
    file << "    a      0x" << std::hex << keyContainer.at("a") << "\n";
    file << "    p      0x" << std::hex << keyContainer.at("p") << "\n";
    
    file << "    alpha  0x" << std::hex << keyContainer.at("alpha") << "\n";
    file << "    beta   0x" << std::hex << keyContainer.at("beta") << "\n";

    file << "}\n";

    file.close();
}


void ELGAMAL::WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    file << "ElgamalEncryptedMessage {\n";
    file << "    Version:    0\n";
    file << "    ContentType:    Text\n";
    file << "    ContentEncryptionAlgorithmIdentifier:    elgamalEncryption\n";
    file << "    encryptedContent:\n";

    for (const bi& num : ciphertext) {
        std::stringstream hexStream;
        hexStream << std::hex << num;
        std::string hexStr = hexStream.str();
        file << "0x" << hexStr << '\n';
    }

    file << "}\n";
    file.close();
}


std::string ELGAMAL::DigitalSigEncrypt(const std::string& HashedPlaintext, const std::string& PrivateKeyFile) {
    auto privateKey = ReadKey(PrivateKeyFile);
    cpp_int a = privateKey["a"];
    cpp_int p = privateKey["p"];

    //THIS IS NOT STANDART BUT IT IS NOT A SECURITY BREACH
    cpp_int alpha = privateKey["alpha"];
    cpp_int beta = privateKey["beta"];

    // THIS IS ALSO A SOLUTION BUT ITS BAD ARCHITECTURE
    // auto publicKey = ReadKey("Digital-signature/Client/Keys/public.key");
    // cpp_int alpha = privateKey["alpha"];
    // cpp_int beta = privateKey["beta"];
    //
    
    
    cpp_int hm = cpp_int(HashedPlaintext);

    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(1, p - 2);
    cpp_int r;
    do {
        r = dist(gen);
    } while (std::get<0>(extended_euclidean_alg(r, p - 1)) != 1);

    cpp_int r_inv = std::get<1>(extended_euclidean_alg(r, p - 1));
    if (r_inv < 0) { r_inv += (p - 1); }
    
    cpp_int gamma = fast_exp_mod(alpha, r, p);
    cpp_int sigma = ((hm - a * gamma) * r_inv) % (p - 1);
    if (sigma < 0) { sigma += (p - 1); }
    
    std::stringstream ss;
    ss << "0x" << std::hex << gamma << ":0x" << std::hex << sigma;
    return ss.str();
}


bool ELGAMAL::DigitalSigValidate(const std::string& EncryptedContent, std::string HashToCompare, const std::string& publicKeyFile) {
    auto publicKey = ReadKey(publicKeyFile);
    cpp_int p = publicKey["p"];
    cpp_int alpha = publicKey["alpha"];
    cpp_int beta = publicKey["beta"];
    
    std::string gamma_str = EncryptedContent.substr(0, EncryptedContent.find(":"));
    std::string sigma_str = EncryptedContent.substr(EncryptedContent.find(":") + 1);

    cpp_int r = cpp_int(gamma_str);
    cpp_int s = cpp_int(sigma_str);

    cpp_int gamma(gamma_str), sigma(sigma_str), hm(HashToCompare);
    cpp_int left_side = (fast_exp_mod(beta, gamma, p) * fast_exp_mod(gamma, sigma, p)) % p;
    cpp_int right_side = fast_exp_mod(alpha, hm, p);
    return left_side == right_side;
}
