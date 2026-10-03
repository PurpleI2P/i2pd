#!/bin/sh
# Fully static i2pd, run from the source tree inside an Alpine container
set -e

OPENSSL_VERSION=3.5.8
JOBS=4

apk add --no-cache build-base perl linux-headers boost-dev boost-static zlib-dev zlib-static miniupnpc-dev

SRC=$(pwd)
cd /tmp
OPENSSL=openssl-$OPENSSL_VERSION
wget -q https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz
wget -q https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz.sha256
echo "$(cut -d' ' -f1 $OPENSSL.tar.gz.sha256)  $OPENSSL.tar.gz" | sha256sum -c -
tar xzf $OPENSSL.tar.gz
cd $OPENSSL
# no-autoload-config: a static binary must not read the host's openssl.cnf
./Configure --prefix=/usr --libdir=lib --openssldir=/nonexistent \
	no-autoload-config no-shared no-module no-dso no-engine no-tests no-docs
make -j$JOBS
make install_sw

cd "$SRC"
# USE_STATIC looks for archives in /usr/lib/$(SYS) and does not pass -static
make -j$JOBS DEBUG=no USE_STATIC=yes USE_UPNP=yes LIBDIR=/usr/lib LDFLAGS=-static i2pd
strip i2pd
