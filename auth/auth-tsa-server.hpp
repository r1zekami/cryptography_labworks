#pragma once

#include "auth-client.hpp"
#include "auth-server.hpp"

#include "../templates/asio-networking-template.h"
#include <iostream>
#include <string>
#include <random>
#include "../cipher-systems/RSA/RSA.h"
#include <boost/property_tree/ptree.hpp>


using boost::property_tree::ptree;

class AuthTSA : public asioLocalNetworkingTemplate
{
public:
    AuthTSA(Proto proto = Proto::BlomKeyExchange) : Proto(proto) {}

    void BlomSequence();
    
    void Run() {
        HandleRequests();
    }

    void HandleRequests()
    {
        if (Proto == Proto::BlomKeyExchange)
        {
            BlomSequence();
        }
    }

private:
    std::string ID = "Key Authority";
    std::string PublicKeyPath = "auth/keys/tsa-keys/public.key";
    std::string PrivateKeyPath = "auth/keys/tsa-keys/private.key";
    std::string PlaintextPath = "auth/temp/plaintext.txt";
    std::string EncryptedTextPath = "auth/temp/encrypted.txt";
    Proto Proto;
};