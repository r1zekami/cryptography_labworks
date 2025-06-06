#include "RSA.h"

void RSA::GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize) {
    cpp_int p = generate_prime(keySize / 2);
    cpp_int q = generate_prime(keySize / 2);

    while (true) {
        if (p == q) {
            q = generate_prime(keySize / 2);
        } else { break; }
    }

    cpp_int n = p * q;
    cpp_int phi = (p - 1) * (q - 1);
    cpp_int e;
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(fast_exp(2, 15), fast_exp(2, 18));

    while (true) { //поиск взаимнопростого e с phi чтобы существовала обратная d
        e = dist(gen);
        if (std::get<0>(extended_euclidean_alg(e, phi)) == 1) {
            break;
        }
    }
    
    e = 65537; //overwrite (stable)
    cpp_int d = std::get<1>(extended_euclidean_alg(e, phi));
    if (d <= 0) d+= phi;
    if ((e * d) % phi != 1) {
        std::cout << "Invalid private key: (e * d) % phi != 1\n";
        return;
    }

    //std::cout << "n: " << n << "\np: " << p << "\nq: " << q << "\ne: " << e << "\nd: " << d << "\nphi: " << phi << "\n";
    
    std::map<std::string, cpp_int> publicKey = {{"e", e}, {"n", n}};
    WritePublicKey(publicKey, publicKeyFile);

    std::map<std::string, cpp_int> privateKey = {
        {"d", d},
        {"n", n},
        {"p", p},
        {"q", q},
        {"exponent1", d % (p - 1)},
        {"exponent2", d % (q - 1)},
        {"coefficient", fast_exp_mod(q, -1, p)}
    };
    WritePrivateKey(privateKey, privateKeyFile);
}


std::vector<cpp_int> RSA::Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile) {
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
    cpp_int e = publicKey["publicExponent"];
    cpp_int n = publicKey["N"];

    std::vector<uint8_t> bytes = TextToBytes(plaintext);
    bytes = PKCS7_Padding(bytes, rsa_encryption_block_size);
    
    std::vector<cpp_int> chunks = ChunkMessage(bytes, rsa_encryption_block_size);
    
    std::vector<cpp_int> ciphertext;
    for (const cpp_int& chunk : chunks) {
        //std::cout << std::hex << chunk << '\n';
        cpp_int c = fast_exp_mod(chunk, e, n);
        ciphertext.push_back(c);
    }

    return ciphertext;
}


std::string RSA::Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile) {
    auto privateKey = ReadKey(privateKeyFile);
    cpp_int d = privateKey["privateExponent"];
    cpp_int n = privateKey["prime1"] * privateKey["prime2"];

    std::ifstream file(ciphertextFile);
    if (!file.is_open()) {
        printf("Failed to open ciphertext file\n");
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

    std::vector<cpp_int> chunks;
    for (cpp_int c : ciphertext) {
        cpp_int m = fast_exp_mod(c, d, n);
        chunks.push_back(m);
    }
    

    std::vector<uint8_t> bytes = UnchunkMessage(chunks, rsa_encryption_block_size);

    bytes = PKCS7_Unpadding(bytes);
    return BytesToText(bytes);
}


void RSA::WritePublicKey(const std::map<std::string, cpp_int>& key, const std::string& keyFile) {
    std::ofstream file(keyFile);
    if (!file.is_open()) {
        std::cout << "Failed to open " << keyFile << " for writing." << std::endl;
        return;
    }

    file << "RSAPublicKey {\n";
    file << "    publicExponent    " << key.at("e") << "  -- Public exponent e\n";
    file << "    N                " << key.at("n") << "  -- n = p*q\n";
    file << "}\n";

    file.close();
}


void RSA::WritePrivateKey(const std::map<std::string, cpp_int>& key, const std::string& keyFile) {
    std::ofstream file(keyFile);
    if (!file.is_open()) {
        std::cout << "Failed to open " << keyFile << " for writing." << std::endl;
        return;
    }

    file << "RSAPrivateKey {\n";
    file << "    privateExponent   " << key.at("d") << "  -- Private exponent d\n";
    file << "    prime1            " << key.at("p") << "  -- Prime factor p of n\n";
    file << "    prime2            " << key.at("q") << "  -- Prime factor q of n\n";
    file << "    exponent1         " << key.at("exponent1") << "  -- d mod (p - 1)\n";
    file << "    exponent2         " << key.at("exponent2") << "  -- d mod (q - 1)\n";
    //file << "    coefficient       " << key.at("coefficient") << "  -- coefficient (q^-1) mod p\n";
    file << "}\n";

    file.close();
}


void RSA::WriteEncryptedMessage(const std::vector<cpp_int>& ciphertext, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cout << "Failed to open file: " + filename << "\n";
    }

    file << "ENCMessage {\n";
    file << "    Version:    0\n";
    file << "    ContentType:    Text\n";
    file << "    ContentEncryptionAlgorithmIdentifier:    rsaEncryption\n";
    file << "    encryptedContent:\n";
    
    for (const cpp_int& num : ciphertext) {
        std::stringstream hexStream;
        hexStream << std::hex << num;
        std::string hexStr = hexStream.str();
        file << "0x" << hexStr << '\n';
    }
    file << "\n}\n";

    file.close();
}


std::string RSA::DigitalSigEncrypt(const std::string& Message, const std::string& PrivateKeyFile, std::function<std::string(std::string)> HashFunction) {

    std::string HashedPlaintext = HashFunction(Message);

    auto privateKey = ReadKey(PrivateKeyFile);
    cpp_int d = privateKey["privateExponent"];
    cpp_int n = privateKey["prime1"] * privateKey["prime2"];
    
    cpp_int Hash(HashedPlaintext);
    cpp_int EncryptedHash = fast_exp_mod(Hash, d, n);
    //std::cout << "ecryptedHash: " << std::hex << encryptedHash << "\n";

    std::stringstream ss;
    ss << "0x" << std::hex << EncryptedHash;
    std::string res = ss.str();
    
    return res;
}


bool RSA::DigitalSigValidate(const std::string& Message, const std::string& SignedContent, std::function<std::string(std::string)> HashFunction, const std::string& publicKeyFile) {
    auto publicKey = ReadKey(publicKeyFile);
    cpp_int e = publicKey["publicExponent"];
    cpp_int n = publicKey["N"];
    std::string HashToCompare = HashFunction(Message);
    
    cpp_int Encrypted = cpp_int(SignedContent);
    cpp_int decrypted = fast_exp_mod(Encrypted, e, n);
    //std::cout << "concatedData: " << Message << "\n";
    //std::cout << "decrypted: " << decrypted << "\n";
    return (decrypted == cpp_int(HashToCompare));
}


boost::property_tree::ptree RSA::GetPublicKeyNode(std::string publicKeyFilePath)
{
    boost::property_tree::ptree keyNode;
    auto publicKey = ReadKey(publicKeyFilePath);
    std::stringstream ss;
    ss << std::hex << publicKey["publicExponent"] << "0x" << publicKey["N"];
    std::string e = "0x" + ss.str().substr(0, ss.str().find("0x"));
    std::string n = "0x" + ss.str().substr(ss.str().find("0x") + 2);
    
    boost::property_tree::ptree KeyNode;
    KeyNode.put("e", e);
    KeyNode.put("n", n);
    return KeyNode;
}


std::map<std::string, cpp_int> RSA::GetPublicKeyContainer(boost::property_tree::ptree propertyTree)
{
    std::string PublicKeyStr_e = propertyTree.get<std::string>("e");
    std::string PublicKeyStr_n = propertyTree.get<std::string>("n");
    return {{"e", cpp_int(PublicKeyStr_e)}, {"n", cpp_int(PublicKeyStr_n)}};
}