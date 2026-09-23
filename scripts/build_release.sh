#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
#
# Build a self-contained libebpfdivert.so (libbpf, libelf, zlib and zstd
# linked in; only glibc is needed at run time) inside a manylinux_2_28
# container, so that it loads on any glibc >= 2.28 distribution and can be
# shipped in manylinux wheels and jars.
#
#   docker run --rm -v "$PWD":/src -w /src quay.io/pypa/manylinux_2_28_$(uname -m) \
#       scripts/build_release.sh <dist-dir>
set -euo pipefail

ZSTD_VERSION=1.5.7
ELFUTILS_VERSION=0.192
DIST="${1:-dist}"
PREFIX_DEPS=/usr/local/ebpfdivert-deps

retry() {
    local i
    for i in 1 2 3 4 5; do "$@" && return 0; echo "retrying: $*" >&2; sleep 5; done
    return 1
}

retry dnf install -y -q clang llvm make pkgconf-pkg-config zlib-devel bzip2 m4 >/dev/null
retry dnf install -y -q --enablerepo=powertools zlib-static >/dev/null

# The distribution's static libelf is not position independent and EL8 has
# no static zstd: build both (PIC) so they can go into the shared library.
if [ ! -f "$PREFIX_DEPS/lib/libelf.a" ]; then
    tmp="$(mktemp -d)"
    mkdir -p "$PREFIX_DEPS/lib" "$PREFIX_DEPS/include"

    curl -fsSL --retry 5 "https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz" \
        | tar -xz -C "$tmp"
    make -s -C "$tmp/zstd-${ZSTD_VERSION}/lib" -j"$(nproc)" libzstd.a CFLAGS="-O2 -fPIC"
    cp "$tmp/zstd-${ZSTD_VERSION}/lib/libzstd.a" "$PREFIX_DEPS/lib/"
    cp "$tmp/zstd-${ZSTD_VERSION}/lib/zstd.h" "$tmp/zstd-${ZSTD_VERSION}/lib/zstd_errors.h" "$PREFIX_DEPS/include/"

    curl -fsSL --retry 5 "https://sourceware.org/elfutils/ftp/${ELFUTILS_VERSION}/elfutils-${ELFUTILS_VERSION}.tar.bz2" \
        | tar -xj -C "$tmp"
    (cd "$tmp/elfutils-${ELFUTILS_VERSION}" &&
        ./configure -q --disable-debuginfod --disable-libdebuginfod --without-bzlib --without-lzma \
            --with-zstd CFLAGS="-O2 -fPIC -I$PREFIX_DEPS/include" LDFLAGS="-L$PREFIX_DEPS/lib" >/dev/null &&
        make -s -C lib -j"$(nproc)" >/dev/null &&
        make -s -C libelf -j"$(nproc)" libelf.a >/dev/null)
    cp "$tmp/elfutils-${ELFUTILS_VERSION}/libelf/libelf.a" "$tmp/elfutils-${ELFUTILS_VERSION}/lib/libeu.a" \
       "$PREFIX_DEPS/lib/"
    cp "$tmp/elfutils-${ELFUTILS_VERSION}/libelf/libelf.h" "$tmp/elfutils-${ELFUTILS_VERSION}/libelf/gelf.h" \
       "$tmp/elfutils-${ELFUTILS_VERSION}/libelf/nlist.h" "$PREFIX_DEPS/include/"
    rm -rf "$tmp"
    mkdir -p "$PREFIX_DEPS/lib/pkgconfig"
    cat > "$PREFIX_DEPS/lib/pkgconfig/libelf.pc" <<PC
prefix=$PREFIX_DEPS
Name: libelf
Description: elfutils libelf (static, PIC)
Version: ${ELFUTILS_VERSION}
Libs: -L\${prefix}/lib -lelf
Libs.private: -leu -lzstd -lz
Cflags: -I\${prefix}/include
PC
fi
export PKG_CONFIG_PATH="$PREFIX_DEPS/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

make clean >/dev/null
make -j"$(nproc)" STATIC_DEPS=1 LDFLAGS="-L$PREFIX_DEPS/lib" \
    LIBBPF_EXTRA_CFLAGS="-I$PREFIX_DEPS/include" EBD_STATIC_LIBS="-lelf -leu -lzstd -lz"
make check

# Only glibc may remain.
if ldd libebpfdivert.so | grep -vE 'linux-vdso|ld-linux|libc\.so|libpthread\.so' | grep -q '=>'; then
    echo "libebpfdivert.so has unexpected dynamic dependencies:" >&2
    ldd libebpfdivert.so >&2
    exit 1
fi

DIST="$(realpath -m "$DIST")"
make install DESTDIR="$DIST" PREFIX=""
cp README.md LICENSE* "$DIST/" 2>/dev/null || true
