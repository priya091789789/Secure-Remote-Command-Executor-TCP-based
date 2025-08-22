#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

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
    
    // Remove trailing newline for execution
    buf[strcspn(buf, "\n")] = '\0';
    
    // Execute command via popen()
    FILE *fp = popen(buf, "r");
    unsigned char status = 0;
    char *output = NULL;
    size_t output_len = 0;

    if (!fp) {
        status = 1;
        const char *err = "Failed to execute command\n";
        output_len = strlen(err);
        output = malloc(output_len);
        memcpy(output, err, output_len);
    } else {
        char chunk[4096];
        size_t nread;
        int timeout_counter = 0;
        const int MAX_TIMEOUT = 5; // 5 seconds timeout
        
        while (1) {
            // Use select to avoid blocking indefinitely
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fileno(fp), &fds);
            struct timeval tv = {1, 0}; // 1 second timeout
            
            int ready = select(fileno(fp)+1, &fds, NULL, NULL, &tv);
            
            if (ready > 0) {
                nread = fread(chunk, 1, sizeof(chunk), fp);
                if (nread > 0) {
                    char *new_output = realloc(output, output_len + nread);
                    if (!new_output) {
                        perror("realloc");
                        break;
                    }
                    output = new_output;
                    memcpy(output + output_len, chunk, nread);
                    output_len += nread;
                    timeout_counter = 0; // Reset timeout counter
                } else {
                    break; // EOF or error
                }
            } else if (ready == 0) {
                // Timeout occurred - check if process is still running
                int status = pclose(fp);
                if (WIFEXITED(status)) {
                    break; // Process exited
                }
                // If still running, reopen pipe and continue
                fp = popen(buf, "r");
                if (++timeout_counter >= MAX_TIMEOUT) {
                    const char *timeout_msg = "\nCommand timed out\n";
                    size_t msg_len = strlen(timeout_msg);
                    char *new_output = realloc(output, output_len + msg_len);
                    if (new_output) {
                        output = new_output;
                        memcpy(output + output_len, timeout_msg, msg_len);
                        output_len += msg_len;
                    }
                    pclose(fp);
                    break;
                }
            } else {
                break; // Select error
            }
        }
    }

    // Print EXACTLY what we're sending to client
    printf("\nServer sending to client:\n");
    printf("Status: %d\n", status);
    printf("Length: %zu\n", output_len);
    if (output_len > 0) {
        printf("Data: ");
        fwrite(output, 1, output_len, stdout);
        printf("\n");
    }

    // Send status
    SSL_write(ssl, &status, 1);
    
    // Send length
    uint32_t net_len = htonl(output_len);
    SSL_write(ssl, &net_len, 4);
    
    // Send data
    if (output_len > 0) {
        SSL_write(ssl, output, output_len);
        free(output);
    }
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
