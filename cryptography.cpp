#include <filesystem>

#include "alghoritms.h"
#include "Elgamal/Elgamal.h"
#include "Rabin/Rabin.h"
#include "RSA/RSA.h"
#include "Hash-functions/hash-functions.h"
#include "Digital-signature/Client/client.hpp"
#include "Digital-signature/Server/server.hpp"

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

    // Client<RSA, SHA512> Client("127.0.0.1", "8888", "MessageToSign");
    // Client.Run();

    // Server server("127.0.0.1", "8889");
    // server.Run();
    int res = 0;
    std::cin >> res;
    
    if (res == 0)
    {
        Server server("127.0.0.1", "8888");
        server.Run();
    } else
    {
        Client<ELGAMAL, SHA512> Client("127.0.0.1", "8888", "MessageToSign");
        Client.Run();
    }

    
    std::cin.get();
    
    return 0;
}