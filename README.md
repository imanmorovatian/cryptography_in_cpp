# Hybrid cryptography using OpenSSL and LiberSSL

In this repo, there is an entity ```Person```. a Person encrypt a message using AES and then enrypt the key used in AES algorithm with RSA (using the public key of the recipient). Finally, it sends the enrypted key and message.

Recipient, fristly decryptes the enrypted key and then decryptes the message with decrypted key.

# How to run
## OpenSSL
```docker build -f Dockerfile.openssl -t openssl-demo .```

then

```docker run --rm openssl-demo```

## LiberSSL
```docker build -f Dockerfile.liberssl -t liberssl-demo .```

then

```docker run --rm liberssl-demo```
