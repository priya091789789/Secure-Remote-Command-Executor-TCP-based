// client.c: Secure Remote Command Executor Client
#define _POSIX_C_SOURCE 200112L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PASS "secret"  // Predefined authentication password

// Initialize SSL context
SSL_CTX* InitSSLContext() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "SSL context creation failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *hostname = argv[1];
    const char *portnum = argv[2];
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1;
    char buffer[4096];
    ssize_t bytes_read;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = InitSSLContext();

    // Trust system CA paths
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
    fprintf(stderr, "Failed to load trusted certs\n");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return EXIT_FAILURE;
}


    // Resolve hostname
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int gai_result = getaddrinfo(hostname, portnum, &hints, &res);
    if (gai_result != 0) {
        fprintf(stderr, "Host resolution failed: %s\n", gai_strerror(gai_result));
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock == -1) {
        fprintf(stderr, "Could not establish connection to %s:%s\n", hostname, portnum);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    SSL_set_fd(ssl, sock);

    // Set hostname for SNI and cert verification
    if (SSL_set1_host(ssl, hostname) != 1) {
        fprintf(stderr, "Failed to set hostname for verification\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Require server certificate verification
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("Connected using %s encryption\n", SSL_get_cipher(ssl));

    // Certificate verification
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Server certificate verification failed\n");
        goto cleanup;
    }

    // Send authentication password
    snprintf(buffer, sizeof(buffer), "%s\n", PASS);
    if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
        fprintf(stderr, "Password send failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Receive auth response
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        fprintf(stderr, "Authentication response failed\n");
        goto cleanup;
    }
    buffer[bytes_read] = '\0';

    if (strncmp(buffer, "Authentication successful", 25) != 0) {
        fprintf(stderr, "Authentication failed: %s", buffer);
        goto cleanup;
    }

    printf("%s", buffer);

    // Command loop
    while (1) {
        printf("cmd> ");
        if (!fgets(buffer, sizeof(buffer), stdin) || feof(stdin)) break;

        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline

        if (strcmp(buffer, "exit") == 0) {
            SSL_write(ssl, buffer, strlen(buffer));
            break;
        }

        strcat(buffer, "\n");  // Re-add newline for server side parsing

        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            fprintf(stderr, "Command send failed\n");
            break;
        }

        // Read server output
        while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            printf("%s", buffer);
            if (bytes_read < sizeof(buffer) - 1) break;
        }

        if (bytes_read <= 0) {
            if (bytes_read < 0) ERR_print_errors_fp(stderr);
            break;
        }
    }

cleanup:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sock != -1) close(sock);
    if (ctx) SSL_CTX_free(ctx);
    EVP_cleanup();
    return EXIT_SUCCESS;
}
