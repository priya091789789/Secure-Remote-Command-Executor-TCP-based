// server.c: Secure command-exec server
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define PASS "secret"  // Hard-coded password (insecure in production)

// Helper to print errors and exit
void berr_exit(const char *msg) {
    perror(msg);
    exit(1);
}

// Initialize SSL context for server (TLS)
SSL_CTX *InitServerCTX(void) {
    const SSL_METHOD *method = TLS_server_method();  // negotiate highest TLS version
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Load server certificate and private key into the SSL context
void LoadCerts(SSL_CTX *ctx, const char *CertFile, const char *KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    char buf[1024], reply[1024];
    int bytes;
    SSL *ssl;
    int port;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 0;
    }
    port = atoi(argv[1]);

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context and load certificate/key
    ctx = InitServerCTX();
    LoadCerts(ctx, "cert.pem", "key.pem");

    SSL_CTX_set_session_id_context(ctx, (unsigned char*)"ctxid", strlen("ctxid"));


    const unsigned char sid_ctx[] = "my_unique_app_ctx";
    if (!SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx))) {
        fprintf(stderr, "Could not set session ID context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Create TCP socket and listen on given port
    server_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) berr_exit("socket");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        berr_exit("bind");
    }
    if (listen(server_fd, 1) != 0) {
        berr_exit("listen");
    }
    printf("Listening on port %d...\n", port);

    // Accept a client connection
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) berr_exit("accept");
    printf("Client connected.\n");

    // Create SSL object and attach to socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    // Perform TLS handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    // Read password from client
    bytes = SSL_read(ssl, buf, sizeof(buf)-1);
    if (bytes <= 0) {
        berr_exit("SSL_read");
        goto cleanup;
    }
    buf[bytes] = '\0';
    // Check password
    buf[strcspn(buf, "\r\n")] = '\0';

    if (strcmp(buf, PASS) != 0) {
        SSL_write(ssl, "Authentication failed\n", 22);
        goto cleanup;
    }
    SSL_write(ssl, "Authentication successful\n", 25);

    // Interactive loop: read commands from client, execute, send back output
    while (1) {
        bytes = SSL_read(ssl, buf, sizeof(buf)-1);
        if (bytes <= 0) break;
        buf[bytes] = '\0';
        if (strcmp(buf, "exit\n") == 0) {
            break;
        }
        // Execute command via popen()
        FILE *fp = popen(buf, "r");
        if (!fp) {
            snprintf(reply, sizeof(reply), "Failed to execute command\n");
            SSL_write(ssl, reply, strlen(reply));
            continue;
        }
        // Send output lines to client
        while (fgets(reply, sizeof(reply), fp) != NULL) {
            SSL_write(ssl, reply, strlen(reply));
        }
        pclose(fp);
    }
    printf("Closing connection.\n");

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
