#ifndef PERSON_H
#define PERSON_H

#include <openssl/evp.h>
#include <string>
#include <vector>

struct EncryptedPackage {
    std::vector<unsigned char> encryptedMessage; /* encrypted message with AES */
    std::vector<unsigned char> encryptedKey; /* key of AES which will be encrypted with RSA */
    std::vector<unsigned char> iv; /* initialization vector for AES */
};

class Person {
public:
    std::string name;
    EVP_PKEY* keyPair;

    Person(const std::string& name);
    ~Person();

    EVP_PKEY* genKeyPair(); 
    std::vector<unsigned char> genRandomKey(size_t keySize = 32);
    std::vector<unsigned char> encryptKey(const std::vector<unsigned char>& key, EVP_PKEY* recipientPubKey);
    EncryptedPackage encryptMessage(const std::string& message, EVP_PKEY* recipientPubKey);
    std::vector<unsigned char> decryptKey(const std::vector<unsigned char>& encryptedKey);
    std::string decryptMessage(const std::vector<unsigned char>& encryptedMessage, std::vector<unsigned char>& encryptedKey, const std::vector<unsigned char>& iv);
};

#endif // PERSON_H
