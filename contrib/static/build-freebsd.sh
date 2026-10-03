#!/bin/sh
# Fully static i2pd for FreeBSD, run from the source tree with the cmake, gmake, perl5, boost-libs and miniupnpc packages
set -e

OPENSSL_VERSION=3.5.8
JOBS=4

SRC=$(pwd)
WORK=${TMPDIR:-/tmp}/i2pd-freebsd
mkdir -p "$WORK"
cd "$WORK"

OPENSSL=openssl-$OPENSSL_VERSION
fetch -q https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz
fetch -q https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz.sha256
[ "$(sha256 -q $OPENSSL.tar.gz)" = "$(cut -d' ' -f1 $OPENSSL.tar.gz.sha256)" ]
tar xzf $OPENSSL.tar.gz
cd $OPENSSL
# no-autoload-config: a static binary must not read the host's openssl.cnf
./Configure --prefix="$WORK/openssl" --libdir=lib --openssldir=/nonexistent \
	no-autoload-config no-shared no-module no-dso no-engine no-tests no-docs
gmake -j$JOBS build_libs
gmake install_dev

cd "$SRC/build"
cmake -DWITH_STATIC=ON -DWITH_UPNP=ON -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$WORK/openssl" .
gmake -j$JOBS
strip i2pd
