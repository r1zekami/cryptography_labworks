#include <filesystem>

#include "alghoritms.h"
#include "auth/auth-client.hpp"
#include "auth/auth-server.hpp"
#include "cipher-systems/ELGAMAL/elgamal.h"
#include "cipher-systems/RABIN/rabin.h"
#include "cipher-systems/RSA/RSA.h"
#include "hash-functions/hash-functions.h"
#include "digita-signature/ds/ds-client/dsi-client.hpp"
#include "digita-signature/group-ds/group-ds-node.hpp"
#include "digita-signature/ds/ds-server/dsi-server.hpp"
#include "cipher-systems/FIAT_SHAMIR/fiat-shamir.h"
#include "cipher-systems/AES/AES.hpp"
#include "digita-signature/group-ds/group-ds-tsa-server.hpp"

bool is_tsa_server() {
    const std::string lock_file = "tsa_server.lock";
    std::ifstream lock_check(lock_file);
    
    if (lock_check.good()) {
        lock_check.close();
        return false;
    }
    lock_check.close();

    std::ofstream lock_create(lock_file);
    if (lock_create.is_open()) {
        lock_create << "TSA server running\n";
        lock_create.close();
        return true;
    }
    
    return false;
}

int main() {
    // std::cout << base64::encode("Helloworld!") << std::endl;
    // std::cout << base64::encode("Helloworld!!") << std::endl;
    // std::cout << base64::encode("Helloworld!!!") << std::endl;
    //
    // std::cout << base64::decode("SGVsbG93b3JsZCE=") << std::endl;
    // std::cout << base64::decode("SGVsbG93b3JsZCEh") << std::endl;
    // std::cout << base64::decode("SGVsbG93b3JsZCEhIQ==") << std::endl;
    //
    //
    // std::cout << base32::encode("Helloworld!") << std::endl;
    // std::cout << base32::encode("Helloworld!!") << std::endl;
    // std::cout << base32::encode("Helloworld!!!") << std::endl;
    // std::cout << base32::encode("Helloworld!!!!") << std::endl;
    // std::cout << base32::encode("Helloworld!!!!!") << std::endl;
    //
    //
    // std::cout << base32::decode("JBSWY3DPO5XXE3DEEE======") << std::endl;
    // std::cout << base32::decode("JBSWY3DPO5XXE3DEEEQQ====") << std::endl;
    // std::cout << base32::decode("JBSWY3DPO5XXE3DEEEQSC===") << std::endl;
    // std::cout << base32::decode("JBSWY3DPO5XXE3DEEEQSCII=") << std::endl;
    // std::cout << base32::decode("JBSWY3DPO5XXE3DEEEQSCIJB") << std::endl;
    
    // std::string messageStr = "abobusIKGASDF,PASKDF;IASJDFMLAISDUJF9Q843RFJORUAFEHNSUIDFNSAIDLFJANSDFOIAJFAORUEWFJRF8FJAWEOIWFJWEIFOJEMFOALIJFEMWFLIOJEIF";
    // uint512_t hash_value = uint512_t(STREEBOG::cyberchefHash256(messageStr));
    // uint512_t hash_value2 = STREEBOG::hash256(messageStr);
    // std::cout << std::hex << hash_value << std::endl;


    // uint64_t num = 0x12345678; // Пример числа
    // std::vector<uint8_t> result = UINTToBytes(num);
    // for (int i = 0; i < result.size(); i++)
    // {
    //     printf("\\0x%x", result[i]);
    // }

    //std::cout << STREEBOG::hash512("Hello world!!!!");
    
    
    // std::vector<uint8_t> bytes1 = {0x12, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0x12, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xAB, 0xAB};
    // uint128_t val1 = bytesToUINT<uint128_t>(bytes1);
    // std::cout << std::hex << val1 << std::endl;

    // std::cout << SHA512::hashMessage("Hello World!!!") << '\n';
    // std::cout << SHA512::hashMessage("Hello World!!!") << '\n';
    // std::cout << SHA512::hashMessage("Hello World!!!") << '\n';
    
    //std::cout << HMAC::hashMessage<SHA512>("Hello World!!!", "1123sdambasdfasdf4ra4warcft55w45sy5ysft54t53gtscwt5f5w5yww534j63") << "\n";
    
    //std::cout << HMAC::hashMessage<SHA256>("Hello World!!!", "1123sd") << "\n";

    //std::cout << STREEBOG512CHEF::hashMessage("Hello World!!Hello World!!Hello World!!Hello World!!Hello World!1");
    
    // std::cout << "HMAC SHA 512:" << HMAC::hashMessage<SHA512>("Hello World!!!", "1123sd") << "\n\n";
    // std::cout << "HMAC SHA 256:" << HMAC::hashMessage<SHA256>("Hello World!!!", "1123sd") << "\n\n";
    // std::cout << "HMAC GOST STRBG 256:" << HMAC::hashMessage<STREEBOG256>("Hello World!!!", "1123sd") << "\n\n";
    // std::cout << "HMAC GOST STRBG 512:" << HMAC::hashMessage<STREEBOG512>("Hello World!!!", "1123sd") << "\n\n";
    // std::cout << "HMAC CHEF STRBG 256:" << HMAC::hashMessage<STREEBOG256CHEF>("Hello World!!!", "1123sd") << "\n\n";
    // std::cout << "HMAC CHEF STRBG 512:" << HMAC::hashMessage<STREEBOG512CHEF>("Hello World!!!", "1123sd") << "\n\n";

    //FIAT_SHAMIR::GenerateKeys("Fiat-Shamir/public.key", "Fiat-Shamir/private.key", SHA256::GetOutputHashSize());
    // std::string SignedContent = FIAT_SHAMIR::DigitalSigEncrypt("Message", "Fiat-Shamir/private.key", SHA256::hashMessage);
    // std::cout << SignedContent << std::endl;
    // std::cout << FIAT_SHAMIR::DigitalSigValidate("Message", SignedContent, SHA256::hashMessage, "Fiat-Shamir/public.key");
    //FIAT_SHAMIR::GetPublicKeyNode("Fiat-Shamir/public.key");
    
    
    // std::vector<uint8_t> plain = { 'h', 'e', 'l', 'l', 'o', 'h', 'e', 'l', 'l', 'o', 'h', 'e', 'l', 'l', 'o', '!'}; //plaintext example
    // std::vector<uint8_t> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
    //
    //
    // std::string plaintext_aes = "Hello World!1234512341234124Hello World!1234512341234124";
    // AES aes(AESKeyLength::AES_128);
    // auto iv = AES::GenerateIV();
    // printf("{");
    // for (int i = 0; i < iv.size(); i++)
    // {
    //     printf("0x%x, ", iv[i]);
    // }
    // printf("} \n");
    // //{0xce, 0xe4, 0xc4, 0x16, 0xc0, 0x10, 0x92, 0xa6, 0xb2, 0x9c, 0xa4, 0x50, 0x70, 0xc, 0x5d, 0x86};
    // auto c = aes.EncryptCBC(stringToBytes(plaintext_aes), key, iv);
    // std::cout << std::string(c.begin(), c.end()) << std::endl;
    //
    // auto d = aes.DecryptCBC(c, key, iv);
    // std::cout << std::string(d.begin(), d.end()) << std::endl;


    // AuthClient Alice;
    // Alice.Run();
    //
    // "REQUEST_AUTH:0xabc655123bbcab3843bca8123bca7124bca71234bca73142" 
    //     ->
    //         "REQUEST_AUTH:{ALICE_TIMESTAMP:Alice:ALICE_DATA}"
    //
    // "RESPONSE_AUTH:0xaadsf2345bca8123bca72345bc432353frstgweqerqr2"
    //     ->
    //         "RESPONSE_AUTH:{ALICE_TIMESTAMP:Bob:BOB_DATA}"
    //
    //
    
    
    /*
    
    int res = 0;
    std::cin >> res;
    if (res == 0) {
        // DSClient<RSA, SHA256> DSClient("127.0.0.1", "8888", "MessageToSign");
        // DSClient.Run();
        
        AuthServer AuthServer("Bob", Proto::SingleUsePasswords);
        AuthServer.Run();
    } else
    {
        // DSServer DSServer("127.0.0.1", "8888");
        // DSServer.Run();
        
        AuthClient AuthClient("Alice", Proto::SingleUsePasswords);
        AuthClient.Run();
    }
    std::cin.get();

    //*/


    
    // AuthServer Bob;
    // Bob.Run();

    //std::cout << mod_inverse(4, 7);

    //std::cout << fast_exp_mod(2, 3, 5);
    
    //GDSNode::GDSCrypto::GenerateAndSaveLeaderKeys();
    
    if (is_tsa_server()) {
     std::cout << "[Main] Starting as TSA server on port 7999\n";
     GDSServer server;
     server.Run();
    } else {
     std::cout << "[Main] TSA server already running, starting as GDS node\n";
     GDSNode node;
     node.Run();
    }
    
    // return 0;
    std::cin.get();
    
    return 0;
}
