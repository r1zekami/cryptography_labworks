#include "rabin.h"


cpp_int RABIN::GenerateRabinPrime(uint64_t keySize) {
    cpp_int prime;
    do {
        prime = generate_prime(keySize);
    } while (prime % 4 != 3);
    return prime;
}


void RABIN::GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize)
{
    cpp_int p = GenerateRabinPrime(keySize);
    cpp_int q = GenerateRabinPrime(keySize);

    while (p == q) {q = GenerateRabinPrime(keySize);}

    cpp_int n = p * q;

    std::cout << p << std::endl;
    std::cout << q << std::endl;
    std::cout << n << std::endl;

    WritePublicKey(publicKeyFile, n);
    WritePrivateKey(privateKeyFile, p, q);        
}



std::string RABIN::addTagsToPlaintext(const std::string& plaintext) {
    std::string result;
    size_t tagLength = std::string(rabin_encryption_tag).length();
    size_t dataPerBlock = rabin_encryption_block_size - tagLength;
    
    size_t pos = 0;
    while (pos < plaintext.length()) {
        result += rabin_encryption_tag;

        size_t dataLength = std::min(dataPerBlock, plaintext.length() - pos);
        result += plaintext.substr(pos, dataLength);
        pos += dataLength;
    }

    return result;
}



std::vector<cpp_int> RABIN::Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile)
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
    cpp_int n = publicKey["n:"];


    plaintext = addTagsToPlaintext(plaintext);
    std::vector<uint8_t> bytes = TextToBytes(plaintext);
    bytes = PKCS7_Padding(bytes, rabin_encryption_block_size);
    
    std::vector<cpp_int> chunks = ChunkMessage(bytes, rabin_encryption_block_size);
    
    std::vector<cpp_int> ciphertext;
    for (const cpp_int& chunk : chunks) {
        cpp_int c = fast_exp_mod(chunk, 2, n);
        ciphertext.push_back(c);
    }

    return ciphertext;
}


std::string RABIN::Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile) {
    auto privateKey = ReadKey(privateKeyFile);
    cpp_int p = privateKey["p"];
    cpp_int q = privateKey["q"];
    cpp_int n = p * q;


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

    auto [gcd, yp, yq] = extended_euclidean_alg(p, q);
    std::vector<uint8_t> decryptedBytes;

    for (auto c : ciphertext)
    {
        cpp_int mp = std::get<0>(solve_2d_congruence(c % p, p));
        cpp_int mq = std::get<0>(solve_2d_congruence(c % q, q));

        // bi mp = fast_exp_mod(c, (p+1) / 4, p);
        // bi mq = fast_exp_mod(c, (q+1) / 4, q);

        cpp_int m1 = (yp * p * mq + yq * q * mp) % n; if (m1 < 0) m1 += n;
        cpp_int m2 = n - m1; if (m2 < 0) m2 += n;
        cpp_int m3 = (yp * p * mq - yq * q * mp) % n; if (m3 < 0) m3 += n;
        cpp_int m4 = n - m3; if (m4 < 0) m4 += n;

        for (auto m : {m1, m2, m3, m4})
        {
            std::vector<uint8_t> blockBytes = UnchunkMessage({m}, rabin_encryption_block_size);
            std::string blockText = BytesToText(blockBytes);
            if (blockText.substr(0, strlen(rabin_encryption_tag.c_str())) == rabin_encryption_tag)
            {
                decryptedBytes.insert(decryptedBytes.end(), blockText.begin(), blockText.end());
                break;
            }
        }
    }
    decryptedBytes = PKCS7_Unpadding(decryptedBytes);
    std::string plaintext = BytesToText(decryptedBytes);
    plaintext = RemoveRabinTags(plaintext);
    
    return plaintext;
}


void RABIN::WritePublicKey(const std::string& publicKeyFile, const cpp_int& n) {
    std::ofstream pubKeyStream(publicKeyFile);
    if (!pubKeyStream.is_open()) {
        std::cout << "Failed to open file for writing public key: " + publicKeyFile << "\n";
        return;
    }

    pubKeyStream << "Rabin Public Key {\n";
    pubKeyStream << "    n: " << n << "\n";
    pubKeyStream << "}\n";

    pubKeyStream.close();
}

void RABIN::WritePrivateKey(const std::string& privateKeyFile, const cpp_int& p, const cpp_int& q) {
    std::ofstream privKeyStream(privateKeyFile);
    if (privKeyStream.is_open()) {
        privKeyStream << "Rabin Private Key {\n";
        privKeyStream << "    p   " << p << "\n";
        privKeyStream << "    q   " << q << "\n";
        privKeyStream << "}\n";
        privKeyStream.close();
    } else {
        throw std::runtime_error("Не удалось открыть файл для записи закрытого ключа.");
    }
}


void RABIN::WriteEncryptedMessage(const std::vector<cpp_int>& ciphertext, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    file << "RabinEncryptedMessage {\n";
    file << "    Version:    0\n";
    file << "    ContentType:    Text\n";
    file << "    ContentEncryptionAlgorithmIdentifier:    rabinEncryption\n";
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


std::string RABIN::RemoveRabinTags(const std::string& input) {
    const std::string tag = rabin_encryption_tag;
    const size_t block_size = rabin_encryption_block_size;
    std::string result;
    size_t total_blocks = input.size() / block_size + (input.size() % block_size != 0);

    for (size_t i = 0; i < total_blocks; ++i) {
        size_t start = i * block_size;
        size_t length = std::min(block_size, input.size() - start);
        std::string block = input.substr(start, length);

        if (block.compare(0, tag.size(), tag) == 0) {
            block.erase(0, tag.size());
        }

        result += block;
    }

    return result;
}

