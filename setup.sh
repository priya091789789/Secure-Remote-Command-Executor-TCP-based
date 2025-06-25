#!/bin/bash
# setup.sh

echo "Setting up Secure Remote Terminal..."

# Compile the programs
echo "Compiling server..."
gcc -o server server.c -lssl -lcrypto

echo "Compiling client..."
gcc -o client client.c -lssl -lcrypto

# Generate certificates if they don't exist
if [ ! -f "cert.pem" ] || [ ! -f "key.pem" ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
fi

echo "Setup complete!"
echo "To run:"
echo "1. Start server: ./server 8443"
echo "2. Start client: ./client localhost 8443"
echo "3. Open index.html in a web browser"