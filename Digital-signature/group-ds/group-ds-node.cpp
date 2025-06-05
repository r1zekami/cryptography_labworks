#pragma once
#include "group-ds-node.hpp"
#include "../../hash-functions/hash-functions.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>

#include "../../CIPHER_SYSTEMS/RSA/RSA.h"

void GDSNode::Run() {
    SelectPort();
    if (my_port_ == -1) {
        std::cout << "[GDSNode] Failed to find a free port. Exiting.\n";
        return;
    }
    if (my_port_ == PORT_RANGE_END)
    {
        isAuthor = true;
        std::cout << "[GDSNode] I AM THE LEADER. \n";
        Leader();
    } else { Member(); }
}

void GDSNode::Leader()
{
    //the great wall of code
    std::cout << "[GDSNode] Leader initialize\n";
    std::map<std::string, cpp_int> LeaderKeys = ReadKey(leaderKeysPath);
    /*
     GDSCrypto::GenerateLeaderKeys();
     GDSCrypto::PregenerateLeaderKeys();
     */
    std::cout << "[GDSNode] Keys saved at <" + leaderKeysPath + ">\n";

    // лидер отправляет каждой ноде сообщение: READY_TO_SERVE:alpha:p
    cpp_int alpha = LeaderKeys["alpha"], p = LeaderKeys["p"], q = LeaderKeys["q"];
    std::string request = "READY_TO_SERVE:" + to_hex(alpha) + ":" + to_hex(p) + ":" + to_hex(q);
    std::cout << "[GDSNode] Leader request <" << request << ">\n";

    // port, PublicKey
    std::map<std::string, cpp_int> memberNodeKeys;
    for (int port = PORT_RANGE_START; port < PORT_RANGE_END; ++port) //leader ++excluded aga
    {
        SendMsg(port, request);
        std::string nodeResponse = ListenAndReceive();
        //std::cout << "[GDSNode] Node response <" << nodeResponse << ">\n";
        std::vector<std::string> parts;
        boost::split(parts, nodeResponse, boost::is_any_of(":"));
        memberNodeKeys[parts[1]] = cpp_int("0x" + parts[2]);
        std::cout << "[GDSNode] Member " << parts[1] << " have pub key: " << std::hex << memberNodeKeys[parts[1]] << "\n";
    }

    //тут пуст ьпока так останется, по идеи тут можно и от мембера получать сообщение которое подписать нужно
    std::string Message;
    //std::cout << "[GDSNode] Enter message to sign: ";
    //std::getline(std::cin, Message);
    Message = "Helloworld";

    //compute_deltas
    std::string hashedMessage = SHA512::hashMessage(Message);
    cpp_int H_M_int = cpp_int(hashedMessage);
    std::map<std::string, cpp_int> delta_j;
    cpp_int U = 1;

    cpp_int d = LeaderKeys["d"], n = LeaderKeys["n"], L = LeaderKeys["L"], z = LeaderKeys["z"];
    for (const auto& [port, P_j] : memberNodeKeys) {
        delta_j[port] = fast_exp_mod((H_M_int + P_j) % n, d, n); // delta_j = (H(M) + P_j)^d mod n
        U = (U * fast_exp_mod(P_j, delta_j[port], p)) % p; // U = П P_j^delta_j mod p
    }
    //endof compute_deltas

    //ask for r 
    std::map<int, cpp_int> R_j;
    for (int port = PORT_RANGE_START; port < PORT_RANGE_END; ++port)
    {
        std::string rRequest = "R_REQUEST:" + to_hex(delta_j[std::to_string(port)]);
        SendMsg(port, rRequest);
        std::string rResponse = ListenAndReceive();
        std::vector<std::string> parts;
        boost::split(parts, rResponse, boost::is_any_of(":"));
        if (parts[0] != "NODE_R_OFFER") return;
        R_j[port] = cpp_int("0x" + parts[2]);
    }
    //endof ask for r

    // calc E and request
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> T_dist(1, (q - 1)/2);
    cpp_int T = T_dist(gen);
    T = cpp_int("2353412014475590222167832025890160934420642513436896031736541230855591892515969995873259727091582234977067308509179841538500874286636903354523398931987782");
    std::cout << std::dec << "[GDSNode] T: " << T << "\n";
    
    cpp_int R_l = fast_exp_mod(alpha, T, p); // R_l = alpha^T mod p
    cpp_int R = R_l;
    for (const auto& [port, R_j_val] : R_j) {
        R = (R * R_j_val) % p; // R = R_l * П R_j mod p
    }

    // E
    std::string message_hex = stringToHex(Message);
    std::string data_to_hash = message_hex + to_hex(R) + to_hex(U);
    std::cout << "[GDSNode] Data to hash (for e): " << data_to_hash << "\n";
    std::string hash_hex = SHA512::hashMessage(data_to_hash);
    cpp_int E = cpp_int(hash_hex);
    std::cout << "[GDSNode] E: " << E << "\n";
    // endof E

    std::map<std::string, cpp_int> S_j;
    for (const auto& [port, _] : memberNodeKeys) {
        SendMsg(std::stoi(port), "E_OFFER:" + to_hex(E));
        std::string response = ListenAndReceive();
        std::vector<std::string> parts;
        boost::split(parts, response, boost::is_any_of(":"));
        if (parts[0] == "NODE_S_OFFER") {
            S_j[parts[1]] = cpp_int("0x" + parts[2]);
            std::cout << "[GDSNode] Received S_j from " << parts[1] << ": " << std::hex << S_j[parts[1]] << "\n";
        }
    }

    //это просто пиздец
    for (const auto& [port, S_j_val] : S_j) {
        cpp_int P_j = memberNodeKeys[port];
        cpp_int check = fast_exp_mod(P_j, -(delta_j[port] * E), p);
        check *= fast_exp_mod(alpha, S_j_val, p);
        check %= p;
        if (check != R_j[stoi(port)]) {
            std::cout << "[GDSNode] Verification failed for member " << port << "\n";
            return;
        }
    }

    cpp_int S_hatch = (T + z * E) % q;
    cpp_int S = S_hatch;
    for (const auto& [port, S_j_val] : S_j) {
        S = (S + S_j_val) % q; // S = S_hatch + Σ S_j mod q
    }
    std::cout << "[GDSNode] Verification successful\n";

    std::string signatureMessage = "SIGNATURE:" + Message + ":" + to_hex(U) + ":" + to_hex(E) + ":" + to_hex(S);
    SendMsg(TSA_PORT, signatureMessage);

    std::string tsa_response = ListenAndReceive();
    
    std::vector<std::string> parts;
    boost::split(parts, tsa_response, boost::is_any_of(":"));
    if (parts[0] == "TIMESTAMP_RESPONSE") {
        // TIMESTAMP_RESPONSE:<message>:<U>:<E>:<S>:<Timestamp>:<Signature>:<e>:<n>

        std::string dataToHash = parts[1] + parts[2] + parts[3] + parts[4]; //<message>:<U>:<E>:<S>
        std::string hashedData = SHA512::hashMessage(dataToHash);
        std::string Timestamp = parts[5];
        std::string Signature = parts[6];
        std::cout << "[GDSNode] 2\n";
        std::map<std::string, cpp_int> tsaKeys;
        tsaKeys["e"] = cpp_int("0x" + parts[7]);
        tsaKeys["n"] =  cpp_int("0x" +parts[8]);
        std::cout << "[GDSNode] 3\n";
        std::string tsaPublicKey = "digital-signature/group-ds/temp/group-ds-lead/tsa_public.key";
        RSA::WritePublicKey(tsaKeys, tsaPublicKey);
        std::cout << "[GDSNode] 4\n";
        std::string concatedData = hashedData + Timestamp;

        std::cout << "[GDSNode] concatedData:" << concatedData << "\n";
        
        if (RSA::DigitalSigValidate(concatedData, Signature, SHA512::hashMessage, tsaPublicKey))
        {
            //хаххаха тса рса
            std::cout << "[GDSNode] TSA RSA signature verification successful\n";

            boost::property_tree::ptree root;
            root.put("CMSVersion", "1");
            root.put("DigestAlgorithmIdentifiers", "SHA512");

            boost::property_tree::ptree encapsulatedContentInfo;
            encapsulatedContentInfo.put("ContentType", "Data");
            encapsulatedContentInfo.put("OCTET_STRING_OPTIONAL", parts[1]);
            root.add_child("EncapsulatedContentInfo", encapsulatedContentInfo);

            boost::property_tree::ptree signerInfos;
            signerInfos.put("CMSVersion", "1");
            signerInfos.put("SignerIdentifier", "GroupLeader (NosovMV)");
            signerInfos.put("DigestAlgorithmIdentifiers", "SHA512");
            signerInfos.put("SignatureAlgorithmIdentifier", "groupdsi");

            boost::property_tree::ptree signatureValue;
            signatureValue.put("U", parts[2]);
            signatureValue.put("E", parts[3]);
            signatureValue.put("S", parts[4]);
            signerInfos.add_child("SignatureValue", signatureValue);

            boost::property_tree::ptree unsignedAttributes;
            unsignedAttributes.put("ObjectIdentifier", "signature-time-stamp");
            boost::property_tree::ptree setOfAttributeValue;
            setOfAttributeValue.put("Timestamp", parts[5]);
            setOfAttributeValue.put("TSASignature", parts[6]);
            boost::property_tree::ptree tsaPublicKey;
            tsaPublicKey.put("e", parts[7]);
            tsaPublicKey.put("n", parts[8]);
            setOfAttributeValue.add_child("TSAPublicKey", tsaPublicKey);
            unsignedAttributes.add_child("SET_OF_AttributeValue", setOfAttributeValue);
            signerInfos.add_child("UnsignedAttributes", unsignedAttributes);

            root.add_child("SignerInfos", signerInfos);
            
            std::ofstream signature_file("digital-signature/group-ds/temp/group-ds-lead/signature.json");
            if (signature_file.is_open()) {
                boost::property_tree::write_json(signature_file, root, true);
                signature_file.close();
                std::cout << "[GDSNode] Signature saved\n";
            } else {
                std::cout << "[GDSNode] Failed to open digital-signature/group-ds/temp/group-ds-lead/signature.json\n";
            }
        } else
        {
            std::cout << "[GDSNode] Invalid RSA Verification\n";
        }
    } else {
        std::cout << "[GDSNode] Invalid TSA response format: " << tsa_response << "\n";
    }
    return;
}

void GDSNode::Member()
{
    std::cout << "[GDSNode] Starting member...\n";
    std::string requestFromLeader = ListenAndReceive();
    std::vector<std::string> parts;
    boost::split(parts, requestFromLeader, boost::is_any_of(":"));
    cpp_int alpha = cpp_int("0x" + parts[1]);
    cpp_int p = cpp_int("0x" + parts[2]);
    cpp_int q = cpp_int("0x" + parts[3]);
    std::map<std::string, cpp_int> keys = GDSCrypto::GenerateMemberKeys(alpha, p, q);
    cpp_int k = keys["k"], P = keys["P"];
    std::string uniqueMemberKeyPath = "digital-signature/group-ds/temp/group-ds-mem/member" + std::to_string(my_port_) + ".key";
    std::ofstream keyFile(uniqueMemberKeyPath);
    keyFile << "memberKey {\n";
    keyFile << "    k    " << keys["k"] << "\n";
    keyFile << "    P    " << P << "\n";
    keyFile << "}\n";
    keyFile.close();
    std::string response = "NODE_PUBLIC_KEY_OFFER:" + std::to_string(my_port_) + ":" + to_hex(P);
    SendMsg(PORT_RANGE_END, response);
    std::cout << "[GDSNode] 12\n";

    // rdeltas
    std::string rRequest = ListenAndReceive();
    std::cout << "[GDSNode] rRequest: " << rRequest << "\n";
    boost::split(parts, rRequest, boost::is_any_of(":"));
    if (parts[0] != "R_REQUEST") return;
    cpp_int delta_j = cpp_int("0x" + parts[1]);
    boost::random::mt19937 gen(std::random_device{}());
    boost::random::uniform_int_distribution<cpp_int> t_dist(1, (q - 1)/2);
    cpp_int t_j = t_dist(gen);
    t_j = cpp_int("5246455459673081758814913022473437788758261049223569578402719036368789471487881224719071763069659520350904949296135932475750272813061528384291590622258245");
    std::cout << "[GDSNode] t_j: " << t_j << "\n";
    
    cpp_int R_j = fast_exp_mod(alpha, t_j, p); // R_j = alpha^t_j mod p
    SendMsg(PORT_RANGE_END, "NODE_R_OFFER:" + std::to_string(my_port_) + ":" + to_hex(R_j));

    // endof rdeltas

    // E
    std::string e_msg = ListenAndReceive();
    boost::split(parts, e_msg, boost::is_any_of(":"));
    if (parts[0] != "E_OFFER") return;
    cpp_int E = cpp_int("0x" + parts[1]);
    cpp_int S_j = (t_j + k * delta_j * E) % q; // S_j = t_j + k_j * delta_j * E mod q
    if (S_j < 0) S_j += q;
    SendMsg(PORT_RANGE_END, "NODE_S_OFFER:" + std::to_string(my_port_) + ":" + to_hex(S_j));
    // endof e

    return;
}