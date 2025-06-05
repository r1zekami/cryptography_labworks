#include "fiat-shamir.h"


void FIAT_SHAMIR::GenerateKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, uint64_t hashFuncOutputSize)
{
    cpp_int p = generate_prime(keySize / 2);
    cpp_int q;
    do {
        q = generate_prime(keySize / 2);
    } while (q == p);
    
    cpp_int n = p*q;
    
    std::vector<cpp_int> a_keys;
    std::vector<cpp_int> b_keys;
    std::map<std::string, cpp_int> publicKeyContainer;
    std::map<std::string, cpp_int> privateKeyContainer;

    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(2, n-1);

    for (uint64_t i = 0; i < hashFuncOutputSize; i++) {
        cpp_int a;
        std::tuple<cpp_int, cpp_int, cpp_int> ext_gcd_an;
        
        do {
            a = dist(gen);
            ext_gcd_an = extended_euclidean_alg(a, n); //проверяем есть ли у а обратный
        } while (std::get<0>(ext_gcd_an) != 1);
        a_keys.push_back(a);

        cpp_int a_inv = std::get<1>(ext_gcd_an); //берем обратный для генерации б
        if (a_inv < 0) { a_inv += n; }
        cpp_int b = (a_inv*a_inv) % n;
        b_keys.push_back(b);
    }
    
    for (uint64_t i = 0; i < hashFuncOutputSize; i++) {
        std::string b_name = "b" + std::to_string(i);
        publicKeyContainer[b_name] = b_keys[i];

        std::string a_name = "a" + std::to_string(i);
        privateKeyContainer[a_name] = a_keys[i];
    }
    publicKeyContainer["n"] = n;
    privateKeyContainer["p"] = p;
    privateKeyContainer["q"] = q;

    WritePublicKey(publicKeyContainer, publicKeyFile);
    WritePrivateKey(privateKeyContainer, privateKeyFile);
}


/*
publicKey {
    "b0": 0x1231,
    "b1": 0x1223,
    "b2": 0x12313,
    ...
    "b511/255": 0x112323,
    "n": 0x123312
}

privateKey {
    "a0": 0x1231,
    "a1": 0x1223,
    "a2": 0x12313,
    ...
    "a511/255": 0x112323,
    "p": 0x123,
    "q": 0x123
}
*/


void FIAT_SHAMIR::WritePublicKey(const std::map<std::string, cpp_int>& key, const std::string& keyFile)
{
    std::ofstream file(keyFile);
    if (!file.is_open()) {
        std::cout << "[FIAT_SHAMIR] Failed to open " << keyFile << " for writing." << std::endl;
        return;
    }

    file << "FIAT_SHAMIR_PUBLIC_KEY {\n";

    for (size_t i = 0; i < key.size() - 1; i++)
    {
        std::string b_name = "b" + std::to_string(i);
        file << "        " << std::left << std::setw(6) << b_name << key.at("b" + std::to_string(i)) << "\n";
    }
    file << "        n     " << key.at("n") << "\n";
    file << "}\n";
    file.close();
}


void FIAT_SHAMIR::WritePrivateKey(const std::map<std::string, cpp_int>& key, const std::string& keyFile)
{
    std::ofstream file(keyFile);
    if (!file.is_open()) {
        std::cout << "[FIAT_SHAMIR] Failed to open " << keyFile << " for writing." << std::endl;
        return;
    }

    file << "FIAT_SHAMIR_PRIVATE_KEY {\n";

    for (size_t i = 0; i < key.size() - 2; i++)
    {
        std::string a_name = "a" + std::to_string(i);
        file << "        " << std::left << std::setw(6) << a_name << key.at("a" + std::to_string(i)) << "\n";
    }
    file << "        p     " << key.at("p") << "\n";
    file << "        q     " << key.at("q") << "\n";
    file << "}\n";
    file.close();
}


std::string FIAT_SHAMIR::DigitalSigEncrypt(const std::string& Message, const std::string& PrivateKeyFile, std::function<std::string(std::string)> HashFunction)
{
    auto privateKey = ReadKey(PrivateKeyFile);
    cpp_int p = privateKey["p"];
    cpp_int q = privateKey["q"];
    cpp_int n = p*q;
    std::vector<cpp_int> a_keys;

    for (int i = 0; i < privateKey.size() - 2; i++)
    {
        std::string a_name = "a" + std::to_string(i);
        cpp_int a = privateKey.at(a_name);
        a_keys.push_back(a);
    }
    
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> dist(1, n-1);
    cpp_int r = dist(gen);

    cpp_int u = (r*r) % n;
    if (u < 0) { u += n; }

    std::stringstream ss;
    ss << std::hex << u;
    std::string u_str =  ss.str();

    //std::cout << "u: " << u_str << "\n\n\n";

    
    cpp_int s = cpp_int{ HashFunction(Message + u_str) };
    cpp_int t = r;

    for (int i = 0; i < a_keys.size(); i++)
    {
        t *= fast_exp_mod(a_keys[i], ((s >> i) & 0x01), n);
    }
    t = t % n;
    ss.clear(); ss.str("");
    ss << "0x" << std::hex << s << ":" << std::hex << "0x" << std::hex << t;
    
    std::string sign = ss.str();
    return sign;
}


bool FIAT_SHAMIR::DigitalSigValidate(const std::string& Message, const std::string& SignedContent, std::function<std::string(std::string)> HashFunction, const std::string& publicKeyFile)
{
    auto publicKey = ReadKey(publicKeyFile);
    cpp_int n = publicKey["n"];
    
    std::vector<cpp_int> b_keys;
    for (size_t i = 0; i < publicKey.size() - 1; i++)
    {
        std::string b_name = "b" + std::to_string(i);
        cpp_int b = publicKey.at(b_name);
        b_keys.push_back(b);
    }
    
    std::string s_str = SignedContent.substr(0, SignedContent.find(":"));
    std::string t_str = SignedContent.substr(SignedContent.find(":") + 1);

    // std::cout << '\n';
    // std::cout << s_str << std::endl;
    // std::cout << t_str << std::endl;
    
    cpp_int t = cpp_int{t_str};
    cpp_int s = cpp_int{s_str};
    cpp_int w = t*t % n;

    for (size_t i = 0; i < b_keys.size(); i++)
    {
        w *= fast_exp_mod(b_keys[i], ((s >> i) & 0x01), n);
    }
    w %= n;

    std::stringstream ss;
    ss << std::hex << w;
    std::string w_str = ss.str();

    //std::cout << "w: " << w_str << std::endl;
    
    cpp_int s_new = cpp_int{HashFunction(Message + w_str)};

    // std::cout << '\n';
    // std::cout << HashFunction(Message + w_str);

    return s == s_new;
}



boost::property_tree::ptree FIAT_SHAMIR::GetPublicKeyNode(std::string publicKeyFilePath) 
{
    auto to_hex = [](cpp_int num) -> std::string
    {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    };
    
    auto publicKey = ReadKey(publicKeyFilePath);
    boost::property_tree::ptree KeyNode;
    
    KeyNode.put("n", "0x" + to_hex(publicKey["n"]));

    for (size_t i = 0; i < publicKey.size() - 1; i++)
    {
        std::string b_name = "b" + std::to_string(i);
        KeyNode.put(b_name, "0x" + to_hex(publicKey[b_name]));
    }
    return KeyNode;
}


std::map<std::string, cpp_int> FIAT_SHAMIR::GetPublicKeyContainer(boost::property_tree::ptree propertyTree) 
{
    std::map<std::string, cpp_int> resultKeyContainer;
    std::string n_str = propertyTree.get<std::string>("n");

    //std::cout << propertyTree.get_child("public_key").size() << std::endl;
    
    for (size_t i = 0; i < propertyTree.size() - 1; i++)
    {
        std::string b_name = "b" + std::to_string(i);
        std::string b_hex_str = propertyTree.get<std::string>(b_name);
        resultKeyContainer[b_name] = cpp_int(b_hex_str);
        //std::cout << b_name << "  " << b_hex_str << std::endl;
    }
    //std::cout << resultKeyContainer.size() << std::endl;
    resultKeyContainer["n"] = cpp_int{n_str};
    return resultKeyContainer;
}

