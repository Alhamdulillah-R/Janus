/*
 * alps_server: BoringSSL TLS 1.3 server that negotiates h2 with ALPS, to exercise the Janus client
 * EncryptedExtensions path. Prints what the client sent in its ALPS settings.
 *
 * usage: alps_server <port> <cert.pem> <key.pem> [new|old] [count]
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/* SETTINGS frame: HEADER_TABLE_SIZE 65536, MAX_CONCURRENT_STREAMS 100, INITIAL_WINDOW_SIZE 65536 */
static const uint8_t server_settings[] = {
    0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
};

/**
 * Choose h2 when the client offers it.
 */
static int select_alpn(SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in, unsigned in_len, void *arg)
{
    static const uint8_t h2[] = {2, 'h', '2'};

    if (SSL_select_next_proto((uint8_t **)out, out_len, h2, sizeof(h2), in, in_len) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

/**
 * Listen on all interfaces at port.
 */
static int listen_on(int port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        perror("listen");
        exit(1);
    }
    return fd;
}

int main(int argc, char **argv)
{
    int port, use_new, count, served = 0, lfd;
    SSL_CTX *ctx;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <port> <cert.pem> <key.pem> [new|old] [count]\n", argv[0]);
        return 2;
    }
    port = atoi(argv[1]);
    use_new = argc < 5 || strcmp(argv[4], "old") != 0;
    count = argc > 5 ? atoi(argv[5]) : 1;

    ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (!SSL_CTX_use_certificate_chain_file(ctx, argv[2])
        || !SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    lfd = listen_on(port);
    printf("listening on %d (alps codepoint %s)\n", port, use_new ? "0x44cd" : "0x4469");
    fflush(stdout);

    while (served < count) {
        int fd = accept(lfd, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        const uint8_t *peer = NULL;
        size_t peer_len = 0, i;
        uint8_t buf[64];

        SSL_set_fd(ssl, fd);
        SSL_set_alps_use_new_codepoint(ssl, use_new);
        SSL_add_application_settings(ssl, (const uint8_t *)"h2", 2, server_settings, sizeof(server_settings));

        if (SSL_accept(ssl) != 1) {
            printf("handshake failed: ");
            ERR_print_errors_fp(stdout);
            printf("\n");
        } else {
            SSL_get0_peer_application_settings(ssl, &peer, &peer_len);
            printf("handshake ok version=%s alps=%d resumed=%d client settings (%zu bytes): ",
                SSL_get_version(ssl), SSL_has_application_settings(ssl), SSL_session_reused(ssl), peer_len);
            for (i = 0; i < peer_len; i++)
                printf("%02x", peer[i]);
            printf("\n");
            SSL_read(ssl, buf, sizeof(buf));
        }
        fflush(stdout);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        served++;
    }
    return 0;
}
