#pragma once
#include "../alghoritms.h"


namespace base32
{
    const std::string base32MappingStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string encode(std::string inputStr);
    std::string decode(std::string inputStr);
};


namespace base64
{
    const std::string base64MappingStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encode(std::string inputStr);
    std::string decode(std::string inputStr);
};


//----------------------------------------------------------------------------------------------------------------------


class STREEBOG
{
public:
    //GOST COMPATIBLE FUNCTIONS (LITTLE ENDIAN)
    static uint512_t hash256(const std::string messageStr);
    static uint512_t hash512(const std::string messageStr);

    //CYBERCHEF COMPATIBLE FUNCTIONS (BIG ENDIAN)
    static std::string cyberchefHash256(const std::string messageStr);
    static std::string cyberchefHash512(const std::string messageStr);
    static std::string toBigEndianHex(const uint512_t& num);
    
    static std::vector<uint8_t> padMessage(const std::vector<uint8_t>& message);
    static constexpr size_t initBlockSizeBytes{64};


private:
    static const uint8_t permutationsPi[256];
    static const uint8_t permutationsTau[64];
    static const uint64_t linearManifold[64];
    static const uint512_t C[12];
    
    static uint512_t X(uint512_t a, uint512_t b);
    static uint512_t S(uint512_t data);
    static uint512_t P(uint512_t data);
    static uint512_t L(uint512_t data);
    static uint512_t LPS(uint512_t x);

    static uint512_t g_N(uint512_t h, uint512_t m, uint512_t N);
    static uint512_t E(uint512_t K, uint512_t m);
    static uint512_t KeySchedule(uint512_t K, int i);
};

//надстройки для шмака ага для шмака ДА ДА 
class STREEBOG256 : public STREEBOG {
public:
    static std::string GetName() { return "STREEBOG256-GOST"; }
    static uint64_t GetOutputHashSize() { return 256; }
    static std::string hashMessage(const std::string& message) {
        return toHexString(STREEBOG::hash256(message));
    }
};

class STREEBOG512 : public STREEBOG {
public:
    static std::string GetName() { return "STREEBOG256-GOST"; }
    static uint64_t GetOutputHashSize() { return 512; }
    static std::string hashMessage(const std::string& message) {
        return toHexString(STREEBOG::hash512(message));
    }
};

class STREEBOG256CHEF : public STREEBOG {
public:
    static std::string GetName() { return "STREEBOG256"; }
    static uint64_t GetOutputHashSize() { return 256; }
    static std::string hashMessage(const std::string& message) {
        return STREEBOG::cyberchefHash256(message);
    }
};

class STREEBOG512CHEF : public STREEBOG {
public:
    static std::string GetName() { return "STREEBOG512"; }
    static uint64_t GetOutputHashSize() { return 512; }
    static std::string hashMessage(const std::string& message) {
        return STREEBOG::cyberchefHash512(message);
    }
};


//----------------------------------------------------------------------------------------------------------------------


class SHA512
{
public:
    static std::string GetName() { return "SHA512"; }
    static uint64_t GetOutputHashSize() { return 512; }
    static std::string hashMessage(std::string messageStr);
    static std::vector<uint8_t> padMessage512(const std::vector<uint8_t>& message);
    static constexpr size_t initBlockSizeBytes{128};

private:
    static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z);
    static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z);
    static uint64_t SIG0(uint64_t x);
    static uint64_t SIG1(uint64_t x);
    static uint64_t sig0(uint64_t x);
    static uint64_t sig1(uint64_t x);

    static const std::array<uint64_t, 80> SHA512Constants;
    static const std::array<uint64_t, 8> H512;
};


//----------------------------------------------------------------------------------------------------------------------


class SHA256
{
public:
    static std::string GetName() { return "SHA256"; }
    static uint64_t GetOutputHashSize() { return 256; }
    static std::string hashMessage(std::string messageStr);
    static std::vector<uint8_t> padMessage256(const std::vector<uint8_t>& message);

    static constexpr size_t initBlockSizeBytes{64};
    
private:
    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t SIG0(uint32_t x);
    static uint32_t SIG1(uint32_t x);
    static uint32_t sig0(uint32_t x);
    static uint32_t sig1(uint32_t x);
    
    static const std::array<uint32_t, 8> H256;
    static const std::array<uint32_t, 64> SHA256Constants;
};


//----------------------------------------------------------------------------------------------------------------------


class HMAC
{
public:
    template<typename HashFunction>
    static std::string hashMessage(std::string message, std::string secretKey)
    {
        const size_t hashFunctionBlockSizeBytes = HashFunction::initBlockSizeBytes;
        std::vector<uint8_t> keyBytes = TextToBytes(secretKey);
        
        if (keyBytes.size() > hashFunctionBlockSizeBytes)
        {
            std::string hashedKey = HashFunction::hashMessage(secretKey);
            //keyBytes = UINTToBytes(cpp_int(hashedKey));
            keyBytes = hexStringToBytes(hashedKey);
        }
        if (keyBytes.size() < hashFunctionBlockSizeBytes)
        {
            keyBytes.insert(keyBytes.end(), hashFunctionBlockSizeBytes - keyBytes.size(), 0x00);
        }
        
        std::vector<uint8_t> ipad(hashFunctionBlockSizeBytes, 0x36);
        std::vector<uint8_t> opad(hashFunctionBlockSizeBytes, 0x5C);
        std::vector<uint8_t> K_xor_ipad(hashFunctionBlockSizeBytes);
        std::vector<uint8_t> K_xor_opad(hashFunctionBlockSizeBytes);
        
        for (size_t i = 0; i < hashFunctionBlockSizeBytes; ++i) {
            K_xor_ipad[i] = keyBytes[i] ^ ipad[i];
            K_xor_opad[i] = keyBytes[i] ^ opad[i];
        }
        
        std::string innerInput = BytesToText(K_xor_ipad) + message; // (K XOR ipad) || M
        std::string innerHash = HashFunction::hashMessage(innerInput); // H[ (K XOR ipad) || M]
        //std::cout << "Got one\n\n";
        
        std::vector<uint8_t> innerHashBytes = hexStringToBytes(innerHash); // H[ (K XOR ipad) || M]
        std::string outerInput = BytesToText(K_xor_opad) + BytesToText(innerHashBytes);
        //std::cout << outerInput.size() << "  " << outerInput << std::endl;
        std::string outerHash = HashFunction::hashMessage(outerInput); // H(K XOR opad, H(K XOR ipad || text))
        //std::cout << "Got two\n\n"; 
        
        return outerHash;
    }
};