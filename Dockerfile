# Use a base image with build tools
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    zlib1g-dev \
    ca-certificates \
    && update-ca-certificates

# Install LibreSSL from source
WORKDIR /opt
RUN wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.9.2.tar.gz && \
    tar -xzf libressl-3.9.2.tar.gz && \
    cd libressl-3.9.2 && \
    ./configure --prefix=/opt/libressl && \
    make -j$(nproc) && \
    make install

# Set up your app
WORKDIR /app
COPY . .

# Compile the C++ program using LibreSSL
RUN g++ -I/opt/libressl/include -L/opt/libressl/lib \
    -Wl,-rpath=/opt/libressl/lib \
    demo.cpp Person.cpp -o demo -lssl -lcrypto

# Run the app
CMD ["./demo"]
