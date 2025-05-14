#include "Person.h"
#include <iostream>

int main() {
    OpenSSL_add_all_algorithms();

    Person alice("Alice");
    Person bob("Bob");
    Person carl("Carl");
    Person edna("Edna");

    std::string message = "This is a test message.";

    // Alice encrypts message for Bob and Edna
    EncryptedPackage packageBob = alice.encryptMessage(message, bob.keyPair);
    EncryptedPackage packageEdna = alice.encryptMessage(message, edna.keyPair);

    for (Person* person : {&bob, &carl, &edna}) {
        std::cout << person->name << " tries to decrypt...\n";
        try {
            EncryptedPackage pkg;
            if (person->name == "Bob") {
                pkg = packageBob;
            } else if (person->name == "Edna") {
                pkg = packageEdna;
            } else {
                pkg = packageBob; // simulate wrong key
            }

            std::string decryptedMessage = person->decryptMessage(pkg.encryptedMessage, pkg.encryptedKey, pkg.iv);
            std::cout << "Success: " << decryptedMessage << "\n\n";
        } catch (...) {
            std::cout << "Failed to decrypt.\n\n";
        }
    }

    EVP_cleanup();

    return 0;
}
