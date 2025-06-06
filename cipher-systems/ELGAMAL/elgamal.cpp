#include "elgamal.h"


cpp_int ELGAMAL::findPrimitive(const cpp_int& p) {
    // (bi alpha = 2; alpha < p; ++alpha) или (bi alpha = p - 2; alpha >= 2; --alpha) влияет ли на стойкость?
    for (cpp_int alpha = p - 2; alpha >= 2; --alpha) {
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

    cpp_int p = generate_prime(keySize);
    cpp_int a = generate_prime(keySize / 2);
    cpp_int alpha = findPrimitive(p); //ну да но нет
    cpp_int beta = fast_exp_mod(alpha, a, p); // beta = alpha^a mod p

    // std::cout << "p: " << p << "\n";
    // std::cout << "a: " << a << "\n";
    // std::cout << "alpha: " << alpha << "\n";
    // std::cout << "beta: " << beta << "\n";
    
    std::map<std::string, cpp_int> publicKey = {
        {"p", p},
        {"alpha", alpha},
        {"beta", beta}
    };
    std::map<std::string, cpp_int> privateKey = {
        {"p", p},

        {"alpha", alpha},
        {"beta", beta},

        {"a", a}
    };

    WritePublicKey(publicKey, publicKeyFile);
    WritePrivateKey(privateKey, privateKeyFile);
    
}



std::vector<cpp_int> ELGAMAL::Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile)
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
    cpp_int p = publicKey["p"];
    cpp_int alpha = publicKey["alpha"]; // ))
    cpp_int beta = publicKey["beta"];

    // for (auto [key, value] : publicKey) {
    //     std::cout << key << " " << value << "\n";
    // }
    
    std::vector<uint8_t> bytes = TextToBytes(plaintext);
    bytes = PKCS7_Padding(bytes, elgamal_encryption_block_size);
    std::vector<cpp_int> chunks = ChunkMessage(bytes, elgamal_encryption_block_size);
    std::vector<cpp_int> ciphertext;

    for (auto chunk : chunks)
    {
        boost::random::mt19937 gen(std::random_device{}());
        boost::random::uniform_int_distribution<cpp_int> dist(0, p - 2);
        cpp_int ephemeral_key = dist(gen);
        cpp_int c1 = fast_exp_mod(alpha, ephemeral_key, p);
        cpp_int c2 = chunk * fast_exp_mod(beta, ephemeral_key, p);

        ciphertext.push_back(c1);
        ciphertext.push_back(c2);
    }

    return ciphertext;
}


std::string ELGAMAL::Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile) {
    auto privateKey = ReadKey(privateKeyFile);
    cpp_int p = privateKey["p"];
    cpp_int a = privateKey["a"];

    std::ifstream file(ciphertextFile);
    if (!file.is_open()) {
        printf("Failed to open ciphertext file");
        return {};
    }

    std::string line;
    std::vector<cpp_int> ciphertext;

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
            cpp_int number;
            std::istringstream iss(line.substr(2));
            iss >> std::hex >> number;
            ciphertext.push_back(number);
        }
    }

    file.close();

    std::vector<uint8_t> decryptedBytes;

    for (size_t i = 0; i < ciphertext.size(); i += 2)
    {
        cpp_int c1 = ciphertext[i];
        cpp_int c2 = ciphertext[i + 1];
        cpp_int c1_inv = fast_exp_mod(c1, a, p);
        
        c1_inv = std::get<1>(extended_euclidean_alg(c1_inv, p));
        cpp_int m = c2 * c1_inv % p;
        if (m < 0) {m += p;}
        
        std::vector<uint8_t> decryptedMessage = UnchunkMessage({m}, elgamal_encryption_block_size);
        decryptedBytes.insert(decryptedBytes.end(), decryptedMessage.begin(), decryptedMessage.end());
    }
    decryptedBytes = PKCS7_Unpadding(decryptedBytes);
    std::string plaintext = BytesToText(decryptedBytes);
    return plaintext;
}



void ELGAMAL::WritePublicKey(const std::map<std::string, cpp_int>& keyContainer, const std::string& keyFile)
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


void ELGAMAL::WritePrivateKey(const std::map<std::string, cpp_int>& keyContainer, const std::string& keyFile)
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


void ELGAMAL::WriteEncryptedMessage(const std::vector<cpp_int>& ciphertext, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    file << "ElgamalEncryptedMessage {\n";
    file << "    Version:    0\n";
    file << "    ContentType:    Text\n";
    file << "    ContentEncryptionAlgorithmIdentifier:    elgamalEncryption\n";
    file << "    encryptedContent:\n";

    for (const cpp_int& num : ciphertext) {
        std::stringstream hexStream;
        hexStream << std::hex << num;
        std::string hexStr = hexStream.str();
        file << "0x" << hexStr << '\n';
    }

    file << "}\n";
    file.close();
}


std::string ELGAMAL::DigitalSigEncrypt(const std::string& Message, const std::string& PrivateKeyFile, std::function<std::string(std::string)> HashFunction) {

    std::string HashedPlaintext = HashFunction(Message);

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

bool ELGAMAL::DigitalSigValidate(const std::string& Message, const std::string& SignedContent, std::function<std::string(std::string)> HashFunction, const std::string& publicKeyFile) {
    auto publicKey = ReadKey(publicKeyFile);
    cpp_int p = publicKey["p"];
    cpp_int alpha = publicKey["alpha"];
    cpp_int beta = publicKey["beta"];
    
    std::string gamma_str = SignedContent.substr(0, SignedContent.find(":"));
    std::string sigma_str = SignedContent.substr(SignedContent.find(":") + 1);

    cpp_int r = cpp_int(gamma_str);
    cpp_int s = cpp_int(sigma_str);

    std::string HashToCompare = HashFunction(Message);
    cpp_int gamma(gamma_str), sigma(sigma_str), hm(HashToCompare);
    cpp_int left_side = (fast_exp_mod(beta, gamma, p) * fast_exp_mod(gamma, sigma, p)) % p;
    cpp_int right_side = fast_exp_mod(alpha, hm, p);
    return left_side == right_side;
}


boost::property_tree::ptree ELGAMAL::GetPublicKeyNode(std::string publicKeyFilePath)
{
    auto publicKey = ReadKey(publicKeyFilePath);
    boost::property_tree::ptree KeyNode;
    KeyNode.put("p", "0x" + to_hex(publicKey["p"]));
    KeyNode.put("alpha", "0x" + to_hex(publicKey["alpha"]));
    KeyNode.put("beta", "0x" + to_hex(publicKey["beta"]));
    return KeyNode;
}


std::map<std::string, cpp_int> ELGAMAL::GetPublicKeyContainer(boost::property_tree::ptree propertyTree)
{
    std::string p_str = propertyTree.get<std::string>("p");
    std::string alpha_str = propertyTree.get<std::string>("alpha");
    std::string beta_str = propertyTree.get<std::string>("beta");
    return {{"p", cpp_int(p_str)},{"alpha", cpp_int(alpha_str)},{"beta", cpp_int(beta_str)}};
}


