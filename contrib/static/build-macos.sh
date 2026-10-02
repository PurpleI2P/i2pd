#!/bin/sh
# Universal i2pd for macOS with OpenSSL, Boost and miniupnpc built from source and linked statically
set -e

OPENSSL_VERSION=3.5.8
BOOST_VERSION=1.92.0
BOOST_SHA256=ea7b982002cc9dfbe59b0b217b206f470dc75f3de0bb2973d844118934d82411
MINIUPNPC_VERSION=2.3.3
MINIUPNPC_SHA256=d52a0afa614ad6c088cc9ddff1ae7d29c8c595ac5fdd321170a05f41e634bd1a
ARCHS="arm64 x86_64"
JOBS=4
export MACOSX_DEPLOYMENT_TARGET=12.0

SRC=$(pwd)
WORK=${TMPDIR:-/tmp}/i2pd-macos
mkdir -p "$WORK"
cd "$WORK"

fetch() {
	curl -fsSL -o "$3" "$1"
	echo "$2  $3" | shasum -a 256 -c -
}

OPENSSL=openssl-$OPENSSL_VERSION
curl -fsSLO https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz
curl -fsSLO https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz.sha256
echo "$(cut -d' ' -f1 $OPENSSL.tar.gz.sha256)  $OPENSSL.tar.gz" | shasum -a 256 -c -
fetch https://github.com/boostorg/boost/releases/download/boost-$BOOST_VERSION/boost-$BOOST_VERSION-b2-nodocs.tar.xz $BOOST_SHA256 boost.tar.xz
fetch https://github.com/miniupnp/miniupnp/releases/download/miniupnpc_$(echo $MINIUPNPC_VERSION | tr . _)/miniupnpc-$MINIUPNPC_VERSION.tar.gz $MINIUPNPC_SHA256 miniupnpc.tar.gz
tar xzf $OPENSSL.tar.gz
tar xJf boost.tar.xz
tar xzf miniupnpc.tar.gz
(cd boost-$BOOST_VERSION && ./bootstrap.sh)

for ARCH in $ARCHS; do
	PREFIX=$WORK/$ARCH
	(
		cd $OPENSSL
		make distclean >/dev/null 2>&1 || true
		# no-autoload-config: a static binary must not read the host's openssl.cnf
		./Configure darwin64-$ARCH-cc --prefix=$PREFIX --libdir=lib --openssldir=/nonexistent \
			no-autoload-config no-shared no-module no-dso no-engine no-tests no-docs
		make -j$JOBS build_libs
		make install_dev
	)
	(
		cd boost-$BOOST_VERSION
		./b2 -j$JOBS --build-dir=$WORK/boost-build-$ARCH --prefix=$PREFIX \
			--with-program_options --with-json --with-url link=static variant=release \
			cxxflags="-arch $ARCH" linkflags="-arch $ARCH" install
	)
	cmake -S miniupnpc-$MINIUPNPC_VERSION -B miniupnpc-build-$ARCH -DCMAKE_OSX_ARCHITECTURES=$ARCH \
		-DCMAKE_INSTALL_PREFIX=$PREFIX -DUPNPC_BUILD_SHARED=OFF -DUPNPC_BUILD_TESTS=OFF -DUPNPC_BUILD_SAMPLE=OFF
	cmake --build miniupnpc-build-$ARCH -j $JOBS
	cmake --install miniupnpc-build-$ARCH
	(
		cd "$SRC"
		make clean >/dev/null
		make -j$JOBS HOMEBREW=1 USE_STATIC=yes USE_UPNP=yes DEBUG=no CXX="clang++ -arch $ARCH" \
			SSLROOT=$PREFIX BOOSTROOT=$PREFIX UPNPROOT=$PREFIX i2pd
		mv i2pd i2pd-$ARCH
	)
done

cd "$SRC"
lipo -create -output i2pd i2pd-arm64 i2pd-x86_64
rm i2pd-arm64 i2pd-x86_64
