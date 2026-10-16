#!/bin/bash
# Build alps_server against BoringSSL and janus_probe against Janus OpenSSL, then handshake janus_probe with the
# chrome155 spec against the server for both ALPS codepoints. Log to /root/alps/test.log.
set -e
build=/root/janus/build/openssl-linux
cd /root/alps
(
    gcc -O1 -c -o alps_server.o alps_server.c -Iboringssl/include
    g++ -o alps_server alps_server.o boringssl/build/libssl.a boringssl/build/libcrypto.a -lpthread
    gcc -O1 -Wall -o /root/janus/tools/janus_probe /root/janus/tools/janus_probe.c -I"$build"/install/include \
        "$build"/install/lib/libssl.a "$build"/install/lib/libcrypto.a -lz -lbrotlienc -lbrotlidec -lbrotlicommon -lzstd -ldl -pthread
    if [ ! -f key.pem ]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 30 -subj /CN=localhost
    fi
    grep -v '^#' /root/alps/chrome155.tls > chrome155-alps.spec
    for codepoint in new old; do
        if [ $codepoint = old ]; then
            sed 's/^raw 44cd /raw 4469 /; s/ 44cd / 4469 /' chrome155-alps.spec > probe.spec
        else
            cp chrome155-alps.spec probe.spec
        fi
        ./alps_server 9443 cert.pem key.pem $codepoint 1 > server-$codepoint.log 2>&1 &
        sleep 1
        echo "== $codepoint client"
        /root/janus/tools/janus_probe probe.spec 127.0.0.1 9443 localhost 1 || true
        wait
        echo "== $codepoint server"
        cat server-$codepoint.log
    done
) > /root/alps/test.log 2>&1
echo EXIT=$? >> /root/alps/test.log
