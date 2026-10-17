#!/bin/bash
# Build static zlib/brotli/zstd and the patched static OpenSSL 4.0.3 for Janus on Linux into build/; reruns are incremental.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
third_party=$root/third_party
deps=$root/build/deps-linux
src=$third_party/openssl
build=$root/build/openssl-linux
# openssl-4.0.3 release commit the patches are written against
base=af1775b60dfa141a4ad762585052cabeb9f37e9e

cmake_lib() {
    local name=$1 source=$2
    shift 2

    cmake -S "$source" -B "$deps/$name" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$deps/install" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        "$@"
    cmake --build "$deps/$name" --target install -j"$(nproc)"
}

cmake_lib zlib "$third_party/zlib" -DZLIB_BUILD_EXAMPLES=OFF
cmake_lib brotli "$third_party/brotli" -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON
cmake_lib zstd "$third_party/zstd/build/cmake" -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_TESTS=OFF
# only the static archives may be found when libcrypto and Janus link
rm -f "$deps"/install/lib/*.so*

if [ ! -d "$src/.git" ]; then
    git clone https://github.com/openssl/openssl "$src"
fi
git -C "$src" checkout -q --detach "$base"
git -C "$src" reset -q --hard "$base"
git -C "$src" clean -qfd
git -C "$src" apply "$root/patches/openssl/0001-janus-clienthello.patch"

mkdir -p "$build"
cd "$build"
if [ ! -f Makefile ]; then
    perl "$src/Configure" linux-x86_64 \
        no-shared \
        no-tests \
        no-docs \
        zlib \
        enable-brotli \
        enable-zstd \
        --with-zlib-include="$deps/install/include" \
        --with-zlib-lib="$deps/install/lib" \
        --with-brotli-include="$deps/install/include" \
        --with-brotli-lib="$deps/install/lib" \
        --with-zstd-include="$deps/install/include" \
        --with-zstd-lib="$deps/install/lib" \
        --prefix="$build/install" \
        --libdir=lib \
        --openssldir="$build/install/ssl"
fi
make -j"$(nproc)" build_sw
make install_sw
echo "OpenSSL installed in $build/install, compression libraries in $deps/install/lib"
