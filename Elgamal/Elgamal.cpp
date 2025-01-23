#include "Elgamal.h"


namespace ELGAMAL
{

    bi findPrimitiveElement(const bi& p) {
        // (bi alpha = p - 2; alpha >= 2; --alpha) роли не играет, на стойкость не влияет
        for (bi alpha = 2; alpha < p; ++alpha) {
            // Он не совсем примитивный, но в рамках лабы обладает нужными свойствами. (c Кирчик)
            //            a^2 != +-1 mod p
            //            a^((p-1)/2) == 1 mod p
            
            if (fast_exp_mod(alpha, 2, p) == 1 || fast_exp_mod(alpha, 2, p) == p - 1) {
                continue;
            }
            if (fast_exp_mod(alpha, (p - 1) / 2, p) == 1) {
                return alpha;
            }
        }
        return 0;
    }

    
    void GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t keySize)
    {

        bi p = generate_prime(keySize);
        bi a = generate_prime(keySize / 2);
        bi alpha = findPrimitiveElement(p); //ну да но нет
        bi beta = fast_exp_mod(alpha, a, p); // beta = alpha^a mod p

        std::cout << "p: " << p << "\n";
        std::cout << "a: " << a << "\n";
        std::cout << "alpha: " << alpha << "\n";
        std::cout << "beta: " << beta << "\n";
        
        WritePublicKey(publicKeyFile, p, alpha, beta);
        WritePrivateKey(privateKeyFile, p, a);
        
        
    }



    std::vector<bi> Encrypt(const std::string& plaintextFile, const std::string& publicKeyFile)
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
        bi p = publicKey["p:"];
        bi alpha = publicKey["alpha:"]; // ))
        bi beta = publicKey["beta:"];

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


    std::string Decrypt(const std::string& ciphertextFile, const std::string& privateKeyFile) {
        auto privateKey = ReadKey(privateKeyFile);
        bi p = privateKey["p:"];
        bi a = privateKey["a:"];

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

    

    void WritePublicKey(const std::string& publicKeyFile, const bi& p, const bi& alpha, const bi& beta)
    {
        std::ofstream pubKeyStream(publicKeyFile);
        if (!pubKeyStream.is_open()) {
            std::cout << "Failed to open file for writing public key: " + publicKeyFile << "\n";
            return;
        }

        pubKeyStream << "Elgamal Public Key {\n";
        pubKeyStream << "    p: " << p << "\n";
        pubKeyStream << "    alpha: " << alpha << "\n";
        pubKeyStream << "    beta: " << beta << "\n";
        pubKeyStream << "}\n";

        pubKeyStream.close();
    }

    
    void WritePrivateKey(const std::string& privateKeyFile, const bi& p, const bi& a)
    {
        std::ofstream privKeyStream(privateKeyFile);
        if (privKeyStream.is_open()) {
            privKeyStream << "Elgamal Private Key {\n";
            privKeyStream << "    p: " << p << "\n";
            privKeyStream << "    a: " << a << "\n";
            privKeyStream << "}\n";
            privKeyStream.close();
        } else {
            throw std::runtime_error("Не удалось открыть файл для записи закрытого ключа.");
        }
    }
    

    void WriteEncryptedMessage(const std::vector<bi>& ciphertext, const std::string& filename) {
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
}
