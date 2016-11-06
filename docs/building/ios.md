Building on iOS
===================

How to build i2pd for iOS 9 and iOS Simulator 386/x64

Prerequisites
--------------

XCode7+, cmake 3.2+

Dependencies
------------

- precompiled openssl
- precompiled boost with modules `filesystem`, `program_options`, `date_time` and `system`
- ios-cmake toolchain from `https://github.com/vovasty/ios-cmake.git`

Building
--------

Assume you have folder structure

	lib/
		libboost_date_time.a
		libboost_filesystem.a
		libboost_program_options.a
		libboost_system.a
		libboost.a
		libcrypto.a
		libssl.a
	include/
		boost/
		openssl/
	ios-cmake/
	i2pd/

```bash
mkdir -p build/simulator/lib build/ios/lib include/i2pd

pushd build/simulator && \
cmake   -DIOS_PLATFORM=SIMULATOR \
        -DPATCH=/usr/bin/patch \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=../../ios-cmake/toolchain/iOS.cmake \
        -DWITH_STATIC=yes \
        -DWITH_BINARY=no \
        -DBoost_INCLUDE_DIR=../../include \
        -DOPENSSL_INCLUDE_DIR=../../include \
        -DBoost_LIBRARY_DIR=../../lib \
        -DOPENSSL_SSL_LIBRARY=../../lib/libssl.a \
        -DOPENSSL_CRYPTO_LIBRARY=../../lib/libcrypto.a \
        ../../i2pd/build && \
make -j16 VERBOSE=1 && \
popd

pushd build/ios
cmake   -DIOS_PLATFORM=OS \
        -DPATCH=/usr/bin/patch \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=../../ios-cmake/toolchain/iOS.cmake \
        -DWITH_STATIC=yes \
        -DWITH_BINARY=no \
        -DBoost_INCLUDE_DIR=../../include \
        -DOPENSSL_INCLUDE_DIR=../../include \
        -DBoost_LIBRARY_DIR=../../lib \
        -DOPENSSL_SSL_LIBRARY=../../lib/libssl.a \
        -DOPENSSL_CRYPTO_LIBRARY=../../lib/libcrypto.a \
        ../../i2pd/build && \
make -j16 VERBOSE=1 && \
popd

libtool -static -o lib/libi2pdclient.a build/*/libi2pdclient.a
libtool -static -o lib/libi2pd.a build/*/libi2pd.a

cp i2pd/*.h include/i2pd
```

Include into project
--------------------

- add all libraries in `lib` folder to `Project linked frameworks`.
- add `libc++` and `libz` libraries from system libraries to `Project linked frameworks`.
- add path to i2p headers to your `Headers search paths`

Alternatively you may use swift wrapper `https://github.com/vovasty/SwiftyI2P.git`
