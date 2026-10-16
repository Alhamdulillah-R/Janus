/*
 * janus_probe: drive one TLS handshake from a Janus spec file.
 *
 * usage: janus_probe <spec|-> <host> <port> <sni> [count]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/janus.h>

#define MAX_VALUES 256

/**
 * Parse one token as a u16, mapping "grease" to the placeholder.
 */
static int parse_u16(const char *tok, uint16_t *out)
{
    char *end;
    unsigned long v;

    if (strcmp(tok, "grease") == 0) {
        *out = JANUS_GREASE;
        return 1;
    }
    v = strtoul(tok, &end, 16);
    if (*end != '\0' || v > 0xffff)
        return 0;
    *out = (uint16_t)v;
    return 1;
}

/**
 * Decode a hex string into a freshly allocated buffer.
 */
static unsigned char *parse_hex(const char *hex, size_t *len)
{
    size_t n = strlen(hex), i;
    unsigned char *buf;

    if (n % 2 != 0)
        return NULL;
    buf = malloc(n / 2 + 1);
    for (i = 0; i < n / 2; i++) {
        unsigned int b;

        if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
            free(buf);
            return NULL;
        }
        buf[i] = (unsigned char)b;
    }
    *len = n / 2;
    return buf;
}

/**
 * Map a list keyword to its JANUS_LIST_* selector.
 */
static int list_selector(const char *key)
{
    static const char *names[] = {
        "extensions",
        "ciphers",
        "groups",
        "key_shares",
        "sigalgs",
        "versions",
    };
    int i;

    for (i = 0; i < JANUS_LIST_COUNT; i++) {
        if (strcmp(key, names[i]) == 0)
            return i;
    }
    return -1;
}

/**
 * Apply one spec line to the context.
 */
static int apply_line(SSL_CTX *ctx, char *line, uint32_t *flags)
{
    char *tok, *save = NULL;
    char *key = strtok_r(line, " \t\r\n", &save);
    int which;

    if (key == NULL || key[0] == '#')
        return 1;

    which = list_selector(key);
    if (which >= 0) {
        uint16_t values[MAX_VALUES];
        size_t n = 0;

        while ((tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
            if (n == MAX_VALUES || !parse_u16(tok, &values[n++]))
                return 0;
        }
        return SSL_CTX_janus_set_list(ctx, which, values, n);
    }

    if (strcmp(key, "raw") == 0) {
        char *type_tok = strtok_r(NULL, " \t\r\n", &save);
        char *hex = strtok_r(NULL, " \t\r\n", &save);
        unsigned char *body = NULL;
        size_t len = 0;
        uint16_t type;
        int ok;

        if (type_tok == NULL || !parse_u16(type_tok, &type))
            return 0;
        if (hex != NULL && (body = parse_hex(hex, &len)) == NULL)
            return 0;
        ok = SSL_CTX_janus_set_raw_extension(ctx, type, body, len);
        free(body);
        return ok;
    }

    if (strcmp(key, "alps") == 0) {
        char *proto = strtok_r(NULL, " \t\r\n", &save);
        char *hex = strtok_r(NULL, " \t\r\n", &save);
        unsigned char *settings = NULL;
        size_t len = 0;
        int ok;

        if (proto == NULL)
            return 0;
        if (hex != NULL && (settings = parse_hex(hex, &len)) == NULL)
            return 0;
        ok = SSL_CTX_janus_set_alps(ctx, (const unsigned char *)proto, strlen(proto), settings, len);
        free(settings);
        return ok;
    }

    if (strcmp(key, "alpn") == 0) {
        unsigned char wire[256];
        size_t n = 0;

        while ((tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
            size_t l = strlen(tok);

            wire[n++] = (unsigned char)l;
            memcpy(wire + n, tok, l);
            n += l;
        }
        return SSL_CTX_set_alpn_protos(ctx, wire, (unsigned int)n) == 0;
    }

    if (strcmp(key, "cert_comp") == 0) {
        int algs[3];
        size_t n = 0;

        while ((tok = strtok_r(NULL, " \t\r\n", &save)) != NULL && n < 3)
            algs[n++] = atoi(tok);
        return SSL_CTX_set1_cert_comp_preference(ctx, algs, n);
    }

    if (strcmp(key, "flag") == 0) {
        tok = strtok_r(NULL, " \t\r\n", &save);
        if (tok != NULL && strcmp(tok, "permute") == 0)
            *flags |= JANUS_FLAG_PERMUTE_EXTENSIONS;
        return 1;
    }

    if (strcmp(key, "ech_grease") == 0) {
        SSL_CTX_set_options(ctx, SSL_OP_ECH_GREASE);
        return 1;
    }

    if (strcmp(key, "ocsp") == 0)
        return SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp);

    fprintf(stderr, "unknown spec key: %s\n", key);
    return 0;
}

/**
 * Open a TCP connection to host:port.
 */
static int dial(const char *host, const char *port)
{
    struct addrinfo hints = { 0 }, *res, *ai;
    int fd = -1;

    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/**
 * Run one handshake, send the h2 preface and an empty SETTINGS frame, then close.
 */
static int run_once(SSL_CTX *ctx, const char *host, const char *port,
    const char *sni)
{
    static const unsigned char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    static const unsigned char settings[] = { 0, 0, 0, 4, 0, 0, 0, 0, 0 };
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    unsigned char buf[4096];
    SSL *ssl;
    int fd, ok = 0;

    fd = dial(host, port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        return 0;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, sni);

    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    printf("ok version=%s cipher=%s group=%s alpn=%.*s grease(c,g,e0,e1,v,s)=%04x,%04x,%04x,%04x,%04x,%04x\n",
        SSL_get_version(ssl),
        SSL_get_cipher_name(ssl),
        SSL_group_to_name(ssl, SSL_get_negotiated_group(ssl)),
        (int)alpn_len, alpn,
        SSL_janus_get_grease_value(ssl, JANUS_LIST_CIPHERS, 0),
        SSL_janus_get_grease_value(ssl, JANUS_LIST_GROUPS, 0),
        SSL_janus_get_grease_value(ssl, JANUS_LIST_EXTENSIONS, 0),
        SSL_janus_get_grease_value(ssl, JANUS_LIST_EXTENSIONS, 1),
        SSL_janus_get_grease_value(ssl, JANUS_LIST_VERSIONS, 0),
        SSL_janus_get_grease_value(ssl, JANUS_LIST_SIGALGS, 0));

    if (SSL_janus_alps_negotiated(ssl)) {
        const unsigned char *peer;
        size_t peer_len = SSL_janus_get_peer_alps(ssl, &peer), j;

        printf("alps negotiated, server settings (%zu bytes): ", peer_len);
        for (j = 0; j < peer_len; j++)
            printf("%02x", peer[j]);
        printf("\n");
    } else {
        printf("alps not negotiated\n");
    }

    if (alpn_len == 2 && memcmp(alpn, "h2", 2) == 0) {
        SSL_write(ssl, preface, sizeof(preface) - 1);
        SSL_write(ssl, settings, sizeof(settings));
        SSL_read(ssl, buf, sizeof(buf));
    }
    ok = 1;

end:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return ok;
}

int main(int argc, char **argv)
{
    char line[8192];
    uint32_t flags = 0;
    FILE *spec;
    SSL_CTX *ctx;
    int count, i, failed = 0;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <spec|-> <host> <port> <sni> [count]\n", argv[0]);
        return 2;
    }
    count = argc > 5 ? atoi(argv[5]) : 1;

    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (strcmp(argv[1], "-") != 0) {
        spec = fopen(argv[1], "r");
        if (spec == NULL) {
            perror("spec");
            return 2;
        }
        while (fgets(line, sizeof(line), spec) != NULL) {
            if (!apply_line(ctx, line, &flags)) {
                fprintf(stderr, "bad spec line\n");
                ERR_print_errors_fp(stderr);
                return 2;
            }
        }
        fclose(spec);
        SSL_CTX_janus_set_flags(ctx, flags);

        if (!SSL_CTX_janus_sync_internal(ctx)) {
            fprintf(stderr, "sync_internal failed\n");
            ERR_print_errors_fp(stderr);
            return 2;
        }
    }

    for (i = 0; i < count; i++) {
        if (!run_once(ctx, argv[2], argv[3], argv[4]))
            failed++;
    }
    SSL_CTX_free(ctx);
    printf("done %d/%d\n", count - failed, count);
    return failed == 0 ? 0 : 1;
}
