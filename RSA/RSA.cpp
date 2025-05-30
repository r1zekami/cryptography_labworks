#include "RSA.h"

#include <boost/mpl/vector/vector0.hpp>


void RSA::GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize) {
    bi p = generate_prime(keySize / 2);
    bi q = generate_prime(keySize / 2);

    while (true) {
        if (p == q) {
            q = generate_prime(keySize / 2);
        } else { break; }
    }

    bi n = p * q;
    bi phi = (p - 1) * (q - 1);
    bi e;
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<bi> dist(fast_exp(2, 15), fast_exp(2, 18));

    while (true) { //поиск взаимнопростого e с phi чтобы существовала обратная d
        e = dist(gen);
        if (std::get<0>(extended_euclidean_alg(e, phi)) == 1) {
            break;
        }
    }
    
    e = 65537; //overwrite (stable)
    bi d = std::get<1>(extended_euclidean_alg(e, phi));
    if (d <= 0) d+= phi;
    if ((e * d) % phi != 1) {
        std::cout << "Invalid private key: (e * d) % phi != 1\n";
        return;
    }

    //std::cout << "n: " << n << "\np: " << p << "\nq: " << q << "\ne: " << e << "\nd: " << d << "\nphi: " << phi << "\n";
    
    std::map<std::string, cpp_int> publicKey = {{"e", e}, {"n", n}};
    WritePublicKey(publicKey, publicKeyFile);

    std::map<std::string, bi> privateKey = {
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


std::vector<bi> RSA::Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile) {
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
    bi e = publicKey["publicExponent"];
    bi n = publicKey["N"];

    std::vector<uint8_t> bytes = TextToBytes(plaintext);
    bytes = PKCS7_Padding(bytes, rsa_encryption_block_size);
    
    std::vector<bi> chunks = ChunkMessage(bytes, rsa_encryption_block_size);
    
    std::vector<bi> ciphertext;
    for (const bi& chunk : chunks) {
        //std::cout << std::hex << chunk << '\n';
        bi c = fast_exp_mod(chunk, e, n);
        ciphertext.push_back(c);
    }

    return ciphertext;
}


std::string RSA::Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile) {
    auto privateKey = ReadKey(privateKeyFile);
    bi d = privateKey["privateExponent"];
    bi n = privateKey["prime1"] * privateKey["prime2"];

    std::ifstream file(ciphertextFile);
    if (!file.is_open()) {
        printf("Failed to open ciphertext file\n");
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

    std::vector<bi> chunks;
    for (bi c : ciphertext) {
        bi m = fast_exp_mod(c, d, n);
        chunks.push_back(m);
    }
    

    std::vector<uint8_t> bytes = UnchunkMessage(chunks, rsa_encryption_block_size);

    bytes = PKCS7_Unpadding(bytes);
    return BytesToText(bytes);
}


void RSA::WritePublicKey(const std::map<std::string, bi>& key, const std::string& keyFile) {
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


void RSA::WritePrivateKey(const std::map<std::string, bi>& key, const std::string& keyFile) {
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


void RSA::WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cout << "Failed to open file: " + filename << "\n";
    }

    file << "ENCMessage {\n";
    file << "    Version:    0\n";
    file << "    ContentType:    Text\n";
    file << "    ContentEncryptionAlgorithmIdentifier:    rsaEncryption\n";
    file << "    encryptedContent:\n";
    
    for (const bi& num : ciphertext) {
        std::stringstream hexStream;
        hexStream << std::hex << num;
        std::string hexStr = hexStream.str();
        file << "0x" << hexStr << '\n';
    }
    file << "\n}\n";

    file.close();
}


std::string RSA::DigitalSigEncrypt(const std::string& HashedPlaintext, const std::string& PrivateKeyFile) {
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


bool RSA::DigitalSigValidate(const std::string& EncryptedContent, const std::string& HashToCompare, const std::string& publicKeyFile) {
    auto publicKey = ReadKey(publicKeyFile);
    bi e = publicKey["publicExponent"];
    bi n = publicKey["N"];
    
    cpp_int Encrypted = cpp_int(EncryptedContent);
    cpp_int decrypted = fast_exp_mod(Encrypted, e, n);
    
    // printf("\n\n");
    // std::cout << HashToCompare << std::endl;
    // std::cout << DecryptedContent << std::endl;
    // printf("\n\n");
    return (decrypted == cpp_int(HashToCompare));
}
