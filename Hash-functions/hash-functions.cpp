#include "hash-functions.h"

using boost::core::rotl, boost::core::rotr;

// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------

std::string base64::encode(std::string inputStr)
{
    size_t stopIndex{0};
    std::string binaryStr;
    std::string result;

    for (char c : inputStr) {
        binaryStr += std::bitset<8>(c).to_string();
    }
    stopIndex = binaryStr.length();
    
    if (binaryStr.size() % 24 != 0) {
        stopIndex = ((binaryStr.size() + 5) / 6) * 6;
        binaryStr.insert(binaryStr.end(), (24 - (binaryStr.size() % 24)), '0');
    }
    
    for (size_t i = 0; i < binaryStr.length(); i+=6)
    {
        std::string tmpBlock = binaryStr.substr(i, 6);
        char newChar{'='};
        
        if (i < stopIndex)
        {
            int tmpBlockMappingIndex = std::stoi(tmpBlock, nullptr, 2);
            newChar = base64MappingStr[tmpBlockMappingIndex];
        }
        result += newChar;
    }
    
    return result;
}


std::string base64::decode(std::string inputStr)
{
    std::string binaryStr;
    std::string result;
    int equalSignNum{0};
    
    for (char c : inputStr)
    {
        if (c == '=')
        {
            ++equalSignNum;
            continue;
        }
        size_t index = base64MappingStr.find(c);
        if (index == std::string::npos) {
            return "Wrong base64 format";
        }
        binaryStr += std::bitset<6>(index).to_string();
    }


    for (size_t i = 0; i < binaryStr.length() - (equalSignNum); i += 8) {
        std::string byteStr = binaryStr.substr(i, 8);
        char byte = static_cast<char>(std::stoi(byteStr, nullptr, 2));
        result += byte; 
    }
    return result;
}   


std::string base32::encode(std::string inputStr)
{
    size_t stopIndex{0};
    std::string binaryStr;
    std::string result;

    for (char c : inputStr) {
        binaryStr += std::bitset<8>(c).to_string();
    }
    stopIndex = binaryStr.length();
    
    if (binaryStr.size() % 40 != 0) {
        stopIndex = ((binaryStr.size() + 4) / 5) * 5;
        binaryStr.insert(binaryStr.end(), (40 - (binaryStr.size() % 40)), '0');
    }
    
    //printf("%s\n", binaryStr.c_str());
    for (size_t i = 0; i < binaryStr.length(); i+=5)
    {
        std::string tmpBlock = binaryStr.substr(i, 5);
        char newChar{'='};
        
        if (i < stopIndex)
        {
            int tmpBlockMappingIndex = std::stoi(tmpBlock, nullptr, 2);
            newChar = base32MappingStr[tmpBlockMappingIndex];
        }
        result += newChar;
    }
    
    return result;

}


std::string base32::decode(std::string inputStr)
{
    std::string binaryStr;
    std::string result;
    int equalSignNum{0};
    
    for (char c : inputStr)
    {
        if (c == '=')
        {
            ++equalSignNum;
            continue;
        }
        size_t index = base32MappingStr.find(c);
        if (index == std::string::npos) {
            return "Wrong base32 format";
        }
        binaryStr += std::bitset<5>(index).to_string();
    }


    for (size_t i = 0; i < binaryStr.length() - (equalSignNum); i += 8) {
        std::string byteStr = binaryStr.substr(i, 8);
        char byte = static_cast<char>(std::stoi(byteStr, nullptr, 2));
        result += byte; 
    }
    
    return result;
}



//----------------------------------------------------------------------------------------------------------------------
//                                                   STREEBOG
//----------------------------------------------------------------------------------------------------------------------



//
// class STREEBOG512 : public HashInterface {
// public:
//     std::string hashMessage(const std::string& message) const override {
//         return STREEBOG::hash512(message).str(16);
//     }   
// };
//
// class STREEBOG256CHEF : public HashInterface {
// public:
//     std::string hashMessage(const std::string& message) const override {
//         return STREEBOG::cyberchefHash256(message);
//     }
// };
//
// class STREEBOG512CHEF : public HashInterface {
// public:
//     std::string hashMessage(const std::string& message) const override {
//         return STREEBOG::cyberchefHash512(message);
//     }
// };







const uint8_t STREEBOG::permutationsPi[256] = { //pi'
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
    };


const uint8_t STREEBOG::permutationsTau[64] = { //t
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33, 41, 49, 57,
    2, 10, 18, 26, 34, 42, 50, 58,
    3, 11, 19, 27, 35, 43, 51, 59,
    4, 12, 20, 28, 36, 44, 52, 60,
    5, 13, 21, 29, 37, 45, 53, 61,
    6, 14, 22, 30, 38, 46, 54, 62,
    7, 15, 23, 31, 39, 47, 55, 63
    };


const uint64_t STREEBOG::linearManifold[64] = {
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083};


const uint512_t STREEBOG::C[12] = {
    uint512_t{"0xb1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507"},
    uint512_t{"0x6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7"},
    uint512_t{"0xf574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2"},
    uint512_t{"0xef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e"},
    uint512_t{"0x4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57"},
    uint512_t{"0xae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e"},
    uint512_t{"0xf4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493"},
    uint512_t{"0x9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e"},
    uint512_t{"0x378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb"},
    uint512_t{"0xabbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced"},
    uint512_t{"0x7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b"},
    uint512_t{"0x378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720"}
};

uint512_t STREEBOG::X(uint512_t k, uint512_t a) { return k ^ a; }

//замена
uint512_t STREEBOG::S(uint512_t data) {
    uint512_t result{0};
    for (int i = 0; i < 64; i++) {
        uint8_t byte = static_cast<uint8_t>((data >> (i * 8)) & 0xFF);
        uint8_t substituted_byte = static_cast<uint8_t>(permutationsPi[byte]);
        result |= (static_cast<uint512_t>(substituted_byte) << (i * 8));
    }
    return result;
}

//перестановка  
uint512_t STREEBOG::P(uint512_t data) {
    uint512_t result{0};
    for (int i = 0; i < 64; i++) {
        uint8_t byte = static_cast<uint8_t>((data >> (i * 8)) & 0xFF);
        int new_position = permutationsTau[i];
        result |= (static_cast<uint512_t>(byte) << (new_position * 8));
    }
    return result;
}


uint512_t STREEBOG::L(uint512_t data) {
    uint8_t input_bytes[64];
    for (int i = 0; i < 64; i++) { //63 - i 
        input_bytes[i] = static_cast<uint8_t>((data >> ((63 - i) * 8)) & 0xFF);  //обратный порядок 63 - i 
    }

    uint8_t output_bytes[64] = {};

    for (int block_idx = 0; block_idx < 8; block_idx++) {

        //восьмибайтный блок
        uint8_t block[8];
        for (int i = 0; i < 8; i++) {
            block[i] = input_bytes[block_idx * 8 + i];
        }

        //переводим восьмибайтный блок в битовое представление в ОБРАТНОМ ПОРЯДКЕ от обратного порядка выше)
        bool bits[64];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = (block[i] >> (7 - j)) & 1;
            }
        }

        //ксорим t с j значением матрицы если есть бит в байте блока (ужас)
        uint64_t t = 0;
        for (int j = 0; j < 64; j++) {
            if (bits[j]) {
                t ^= linearManifold[j];
            }
        }

        for (int i = 0; i < 8; i++) {
            output_bytes[(7 - block_idx) * 8 + i] = static_cast<uint8_t>((t >> (i * 8)) & 0xFF);
        }
    }

    uint512_t result = 0;
    for (int i = 0; i < 64; i++) {
        result |= static_cast<uint512_t>(output_bytes[i]) << (i * 8);
    }

    return result;
}


//
uint512_t STREEBOG::LPS(uint512_t x) {
    x = L(P(S(x)));
    //std::cout << "LPS in: " << std::hex << x << "\n\n";
     //x = S(x);
     //std::cout << "S: " << std::hex << x << "\n\n";
     //x = P(x);
     //std::cout << "P: " << std::hex << x << "\n\n";
     //x = L(x);
     //std::cout << "L: " << std::hex << x << "\n\n";
    return x;
}


//
uint512_t STREEBOG::g_N(uint512_t N, uint512_t m, uint512_t h) {
    uint512_t K = LPS(X(h, N));
    uint512_t t = E(K, m);
    t = X(h, t);
    uint512_t G = X(t, m);
    return G;
}


//
uint512_t STREEBOG::E(uint512_t K, uint512_t m) {
    uint512_t state = X(K, m);
    //std::cout << "X[K,m]: " << std::hex << state << std::endl; //
    for (int i = 0; i < 12; i++)
    {
        state = LPS(state);
        K = KeySchedule(K, i);
        //std::cout << "LPS[K" << std::dec << i << "]: " << std::hex << K <<  "\n";
        state = X(state, K);
        //std::cout << "LPSX[K" << std::dec <<  i << "]: " << std::hex << state << "\n";
    }
    return state;
}


//
uint512_t STREEBOG::KeySchedule(uint512_t K, int i)
{
    K = LPS(X(K, C[i]));
    return K;
}


uint512_t STREEBOG::hash512(const std::string messageStr) {

    std::vector<uint8_t> message = TextToBytes(messageStr);
    // std::vector<uint8_t> message = {
    //     0xfb, 0xe2, 0xe5, 0xf0, 0xee, 0xe3, 0xc8, 0x20, 0xfb, 0xea, 0xfa, 0xeb, 0xef, 0x20,
    //     0xff, 0xfb, 0xf0, 0xe1, 0xe0, 0xf0, 0xf5, 0x20, 0xe0, 0xed, 0x20, 0xe8, 0xec, 0xe0,
    //     0xeb, 0xe5, 0xf0, 0xf2, 0xf1, 0x20, 0xff, 0xf0, 0xee, 0xec, 0x20, 0xf1, 0x20, 0xfa,
    //     0xf2, 0xfe, 0xe5, 0xe2, 0x20, 0x2c, 0xe8, 0xf6, 0xf3, 0xed, 0xe2, 0x20, 0xe8, 0xe6,
    //     0xee, 0xe1, 0xe8, 0xf0, 0xf2, 0xd1, 0x20, 0x2c, 0xe8, 0xf0, 0xf2, 0xe5, 0xe2, 0x20, 0xe5, 0xd1};


    uint512_t h = 0; //iv
    uint512_t N = 0; //512 == 512^0
    uint512_t sum = 0;
    uint512_t m = 0;
    
    while (message.size() >= 64)
    {
        //std::cout << "Got one\n";
        m = bytesToUINT<uint512_t>({std::vector<uint8_t>(message.end() - 64, message.end())}); //последние 512 бит сообщения
        //std::cout << "m: " << std::hex << m << "\n";
        h = g_N(N, m, h);
        N += 512;
        sum += m;
        message.resize(message.size() - 64);
    }
    
    uint512_t originalMessageLength = message.size() * 8;
    std::vector<uint8_t> paddedMessage = padMessage(message);

    // for (int i = 0; i < paddedMessage.size(); i++)
    // {
    //     printf("%02X|", paddedMessage[i]);
    // }
    //std::cout << paddedMessage.size() << std::endl;
    
    //std::cout << "Got two\n";
    m = bytesToUINT<uint512_t>(paddedMessage);

    // for (size_t i = 0; i < paddedMessage.size(); i++) { printf("\\0x%x", paddedMessage[i]); }
    // printf("\npadded dsize is %llu\n", paddedMessage.size());

    //std::cout << std::hex << m << std::endl;
    
    h = g_N(N, m, h);
    //std::cout << "h1: " << std::hex << h <<  "\n";

    N += originalMessageLength;
    //std::cout << "N: " << std::hex << N <<  "\n";

    sum += m;
    //std::cout << "sum: " << std::hex << sum <<  "\n";

    h = g_N(0, N, h);
    //std::cout << "h2: " << std::hex << h <<  "\n";

    h = g_N(0, sum, h);
    //std::cout << "h3: " << std::hex << h <<  "\n";
    
    return h;
}


uint512_t STREEBOG::hash256(const std::string messageStr)
{
    std::vector<uint8_t> message = TextToBytes(messageStr);
    std::vector<uint8_t> iv(64, 0x01);
    uint512_t h = bytesToUINT<uint512_t>(iv); //iv нужно сделать 0x01 x64
    uint512_t N = 0;
    uint512_t sum = 0;
    uint512_t m = 0;
    
    while (message.size() >= 64)
    {
        m = bytesToUINT<uint512_t>({std::vector<uint8_t>(message.end() - 64, message.end())});
        h = g_N(N, m, h);
        N += 512;
        sum += m;
        message.resize(message.size() - 64);
    }
    
    uint512_t originalMessageLength = message.size() * 8;
    std::vector<uint8_t> paddedMessage = padMessage(message);

    
    m = bytesToUINT<uint512_t>(paddedMessage);

    h = g_N(N, m, h);
    N += originalMessageLength;
    sum += m;
    h = g_N(0, N, h);
    h = g_N(0, sum, h);

    //const uint512_t mask = (~uint512_t(0) << 256);
    //~ побитовое не
    return (h & (~uint512_t(0) << 256)) >> 256;
}


std::string STREEBOG::cyberchefHash256(const std::string messageStr)
{
    std::vector<uint8_t> message = TextToBytes(messageStr);
    std::reverse(message.begin(), message.end());

    std::vector<uint8_t> iv(64, 0x01);
    uint512_t h = bytesToUINT<uint512_t>(iv);
    uint512_t N = 0;
    uint512_t sum = 0;
    uint512_t m = 0;
    
    while (message.size() >= 64) {
        m = bytesToUINT<uint512_t>({std::vector<uint8_t>(message.end() - 64, message.end())});
        h = g_N(N, m, h);
        N += 512;
        sum += m;
        message.resize(message.size() - 64);
    }
    
    uint512_t originalMessageLength = message.size() * 8;
    std::vector<uint8_t> paddedMessage = padMessage(message);

    
    m = bytesToUINT<uint512_t>(paddedMessage);
    h = g_N(N, m, h);
    N += originalMessageLength;
    sum += m;
    h = g_N(0, N, h);
    h = g_N(0, sum, h);

    return "0x" + toBigEndianHex((h & (~uint512_t(0) << 256)) >> 256).erase(64, 64);
}


std::string STREEBOG::cyberchefHash512(const std::string messageStr)
{
    std::string reversedStr(messageStr.rbegin(), messageStr.rend());
    uint512_t hash = hash512(reversedStr);
    return "0x" + toBigEndianHex(hash);
}

//написать шаблонную функцию для перевода в байты из числа и наобороти переделать
std::string STREEBOG::toBigEndianHex(const uint512_t& num) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(128) << num; // 128 символов = 64 байта
    std::string littleEndian = oss.str();
    std::string bigEndian;
    for (int i = 126; i >= 0; i -= 2) {
        bigEndian += littleEndian.substr(i, 2);
    }
    return bigEndian;
}


std::vector<uint8_t> STREEBOG::padMessage(const std::vector<uint8_t>& message) {
    std::vector<uint8_t> padded = message;
    padded.insert(padded.begin(), 0x01);
    while (padded.size() % 64 != 0) {
        padded.insert(padded.begin(), 0x00);
    }
    return padded;
}
    


//----------------------------------------------------------------------------------------------------------------------
//                                                     SHA 512
//----------------------------------------------------------------------------------------------------------------------

const std::array<uint64_t, 80> SHA512::SHA512Constants= {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

const std::array<uint64_t, 8> SHA512::H512 = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

uint64_t SHA512::Ch(uint64_t x, uint64_t y, uint64_t z)  { return (x & y) ^ (~x & z);           }
uint64_t SHA512::Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z);  }
uint64_t SHA512::SIG0(uint64_t x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);       }
uint64_t SHA512::SIG1(uint64_t x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);       }
uint64_t SHA512::sig0(uint64_t x) { return rotr(x, 1)  ^ rotr(x, 8)  ^ (x >> 7);            }
uint64_t SHA512::sig1(uint64_t x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);            }

std::string SHA512::hashMessage(std::string messageStr)
{
    std::array<uint64_t, 8> H = H512;
    //std::vector<uint8_t> message = TextToBytes(messageStr);
    std::vector<uint8_t> paddedMessage = padMessage512(TextToBytes(messageStr));
    std::vector<std::vector<uint64_t>> blocks;

    // for (int i = 0; i < paddedMessage.size(); i++)
    // {
    //     printf("\\0x%x", paddedMessage[i]);
    // }
    // printf("\n\n");
    // return std::string("");
    
    for (size_t i = 0; i < paddedMessage.size(); i += 128)
    {
        std::vector<uint64_t> blockWords(16, 0);

        for (size_t j = 0; j < 16; ++j)
        {
            uint64_t word = 0;
            //8 байт 64 бита
            for (size_t k = 0; k < 8; ++k)
            {
                word = (word << 8) | paddedMessage[i + j * 8 + k];
            }
            blockWords[j] = word;
        }
        blocks.push_back(blockWords);
    }

    for (const auto& block : blocks)
    {
        std::vector<uint64_t> W(80, 0);
        for (size_t t = 0; t < 16; ++t)
        {
            W[t] = block[t];
        }

        for (size_t t = 16; t < 80; ++t)
        {
            W[t] = sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16];
        }

        uint64_t a = H[0], b = H[1], c = H[2], d = H[3],
                 e = H[4], f = H[5], g = H[6], h = H[7];

        for (int t = 0; t < 80; ++t)
        {
            uint64_t T1 = h + SIG1(e) + Ch(e, f, g) + SHA512Constants[t] + W[t];
            uint64_t T2 = SIG0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    
    std::string result;
    for (uint64_t value : H)
    {
        //std::cout << std::hex << value << std::endl;
        result += concateUINT64Hexes(value);
    }

    return "0x" + result;
}


std::vector<uint8_t> SHA512::padMessage512(const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> padded = message;
    
    padded.push_back(0x80);
    padded.insert(padded.end(), (128 - ((padded.size() + 16) % 128)) % 128, 0x00);
    uint128_t originalMessageLength = message.size() * 8;
    std::vector<uint8_t> lengthBlock = UINTToBytes(originalMessageLength);
    padded.insert(padded.end(), lengthBlock.begin(), lengthBlock.end());
    
    return padded;
}



//----------------------------------------------------------------------------------------------------------------------
//                                                     SHA 256
//----------------------------------------------------------------------------------------------------------------------



const std::array<uint32_t, 8> SHA256::H256 = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};
    
const std::array<uint32_t, 64> SHA256::SHA256Constants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t SHA256::Ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z);          }
uint32_t SHA256::Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
uint32_t SHA256::SIG0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
uint32_t SHA256::SIG1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
uint32_t SHA256::sig0(uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18)  ^ (x >> 3);      }
uint32_t SHA256::sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);      }


std::string SHA256::hashMessage(std::string messageStr)
{
    std::array<uint32_t, 8> H = H256;
    std::vector<uint8_t> message = TextToBytes(messageStr);
    std::vector<uint8_t> paddedMessage = padMessage256(message);
    std::vector<std::vector<uint32_t>> blocks;

    // for (int i = 0; i < paddedMessage.size(); i++)  {
    //     printf("\\0x%x", paddedMessage[i]);
    // }
    
    //printf("\n\n");

    //std::cout << paddedMessage.size();
    //return "123";
    //printf("\n\n");

    for (size_t i = 0; i < paddedMessage.size(); i += 64)
    {
        std::vector<uint32_t> blockWords(16, 0);

        for (size_t j = 0; j < 16; ++j)
        {
            uint32_t word = 0;

            // 4 байта 32 бита
            for (size_t k = 0; k < 4; ++k)
            {
                word = (word << 8) | paddedMessage[i + j * 4 + k];
            }

            blockWords[j] = word;
        }

        blocks.push_back(blockWords);
    }   

    // for (const auto& block : blocks)
    // {
    //     for (const auto& word : block)
    //     {
    //         std::cout << std::hex << word << std::endl;
    //     }
    // }

    for (const auto& block : blocks)
    {
        std::vector<uint32_t> W(64, 0);
        for (size_t t = 0; t < 16; ++t)
        {
            W[t] = block[t];
        }

        for (size_t t = 16; t < 64; ++t)
        {
            W[t] = sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16];
        }

        uint32_t a = H[0], b = H[1], c = H[2], d = H[3],
                 e = H[4], f = H[5], g = H[6], h = H[7];

        for (int t = 0; t < 64; ++t)
        {
            uint32_t T1 = h + SIG1(e) + Ch(e, f, g) + SHA256Constants[t] + W[t];
            uint32_t T2 = SIG0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    
    std::string result;
    for (uint32_t value : H)
    {
        //std::cout << std::hex << value << std::endl;
        result += concateUINT32Hexes(value);
    }

    return "0x" + result;   
}


std::vector<uint8_t> SHA256::padMessage256(const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> padded = message;

    padded.push_back(0x80);
    padded.insert(padded.end(), (64 - ((padded.size() + 8) % 64)) % 64, 0x00);

    uint64_t originalMessageLength = message.size() * 8;
    std::vector<uint8_t> lengthBlock = UINTToBytes(originalMessageLength);
    
    padded.insert(padded.end(), lengthBlock.begin(), lengthBlock.end());
    
    return padded;
}


//----------------------------------------------------------------------------------------------------------------------
//                                                     HMAC
//----------------------------------------------------------------------------------------------------------------------

