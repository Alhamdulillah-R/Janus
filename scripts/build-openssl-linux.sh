#!/bin/bash
# Build the patched static OpenSSL 4.0.3 for Janus on Linux into build/openssl-linux/install (system zlib, brotli, zstd).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
src=$root/third_party/openssl
build=$root/build/openssl-linux
# openssl-4.0.3 release commit the patches are written against
base=af1775b60dfa141a4ad762585052cabeb9f37e9e

if [ ! -d "$src/.git" ]; then
    git clone https://github.com/openssl/openssl "$src"
fi
git -C "$src" checkout -q --detach "$base"
git -C "$src" reset -q --hard "$base"
git -C "$src" apply "$root/patches/openssl/0001-janus-clienthello.patch"

mkdir -p "$build"
cd "$build"
if [ ! -f Makefile ]; then
    perl "$src/Configure" linux-x86_64 \
        no-shared \
        no-tests \
        no-docs \
        enable-brotli \
        enable-zstd \
        zlib \
        --prefix="$build/install" \
        --libdir=lib \
        --openssldir="$build/install/ssl"
fi
make -j"$(nproc)" build_sw
make install_sw
echo "OpenSSL installed in $build/install"
