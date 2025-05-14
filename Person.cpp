#include "Person.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>

using namespace std;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

Person::Person(const std::string& name) : name(name) {
    keyPair = genKeyPair();
}

Person::~Person() {
    if (keyPair) EVP_PKEY_free(keyPair);
}

EVP_PKEY* Person::genKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr); /* create a context for RSA key generation */
    EVP_PKEY* keyPair = nullptr;

    EVP_PKEY_keygen_init(ctx); /* initialize the context */
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048); /* set the key size to 2048 bits */
    EVP_PKEY_keygen(ctx, &keyPair); /* generate the key */
    EVP_PKEY_CTX_free(ctx); /* clean up the context */
    return keyPair;
}

std::vector<unsigned char> Person::genRandomKey(size_t keySize) {
    std::vector<unsigned char> key(keySize);
    RAND_bytes(key.data(), keySize); /* cryptographically secure randomness */
    return key;
}

std::vector<unsigned char> Person::encryptKey(const std::vector<unsigned char>& key, EVP_PKEY* recipientPublicKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(recipientPublicKey, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, key.data(), key.size()) <= 0)
        handleErrors();

    std::vector<unsigned char> encryptedKey(outlen);
    if (EVP_PKEY_encrypt(ctx, encryptedKey.data(), &outlen, key.data(), key.size()) <= 0)
        handleErrors();

    encryptedKey.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return encryptedKey;
}

EncryptedPackage Person::encryptMessage(const std::string& message, EVP_PKEY* recipientPublicKey) {
    std::vector<unsigned char> key = genRandomKey(32);
    std::vector<unsigned char> iv = genRandomKey(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;
    std::vector<unsigned char> ciphertext(message.size() + EVP_MAX_BLOCK_LENGTH);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)message.data(), message.size()))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        handleErrors();
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> encryptedKey = encryptKey(key, recipientPublicKey);
    return {ciphertext, encryptedKey, iv};
}

std::vector<unsigned char> Person::decryptKey(const std::vector<unsigned char>& encryptedKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keyPair, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encryptedKey.data(), encryptedKey.size()) <= 0)
        throw std::runtime_error("RSA decrypt failed");

    std::vector<unsigned char> key(outlen);
    if (EVP_PKEY_decrypt(ctx, key.data(), &outlen, encryptedKey.data(), encryptedKey.size()) <= 0)
        throw std::runtime_error("RSA decrypt failed");

    key.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

std::string Person::decryptMessage(const std::vector<unsigned char>& encryptedMessage,
std::vector<unsigned char>& encryptedKey,
const std::vector<unsigned char>& iv) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    int len;
    int plaintext_len;
    std::vector<unsigned char> plaintext(encryptedMessage.size());
    std::vector<unsigned char> key = decryptKey(encryptedKey);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()))
        throw std::runtime_error("DecryptInit failed");

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, encryptedMessage.data(), encryptedMessage.size()))
        throw std::runtime_error("DecryptInit failed");

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        throw std::runtime_error("DecryptFinal failed (likely bad key or tampered message)");
        
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());

}
