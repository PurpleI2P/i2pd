Cross compilation notes
=======================

Static 64 bit windows binary on Ubuntu 15.10 (Wily Werewolf)
------------------------------------------------------------

Install cross compiler and friends

	sudo apt-get install g++-mingw-w64-x86-64

Default is to use Win32 threading model which lacks std::mutex and such. So we change defaults

	sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix

From now on we assume we have everything in `~/dev/`. Get Boost sources unpacked into `~/dev/boost_1_60_0/` and change directory to it.
Now add out cross compiler configuration. Warning: the following will wipe out whatever you had in there.

	echo "using gcc : mingw : x86_64-w64-mingw32-g++ ;" > ~/user-config.jam

Proceed with building Boost normal way, but let's define dedicated staging directory

	./bootstrap.sh
	./b2 toolset=gcc-mingw target-os=windows variant=release link=static runtime-link=static address-model=64 \
	  --build-type=minimal --with-filesystem --with-program_options --with-date_time \
	  --stagedir=stage-mingw-64
	cd ..

Now we get & build OpenSSL

	git clone https://github.com/openssl/openssl
	cd openssl
	git checkout OpenSSL_1_0_2g
	./Configure mingw64 no-rc2 no-rc4 no-rc5 no-idea no-bf no-cast no-whirlpool no-md2 no-md4 no-ripemd no-mdc2 \
	  no-camellia no-seed no-comp no-krb5 no-gmp no-rfc3779 no-ec2m no-ssl2 no-jpake no-srp no-sctp no-srtp \
	  --prefix=~/dev/stage --cross-compile-prefix=x86_64-w64-mingw32-
	make depend
	make
	make install
	cd ..

...and zlib

	git clone https://github.com/madler/zlib
	cd zlib
	git checkout v1.2.8
	CC=x86_64-w64-mingw32-gcc CFLAGS=-O3 ./configure --static --64 --prefix=~/dev/stage
	make
	make install
	cd ..

Now we prepare cross toolchain hint file for CMake, let's name it `~/dev/toolchain-mingw.cmake`

	set(CMAKE_SYSTEM_NAME Windows)
	set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
	set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
	set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
	set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
	set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

Download miniupnpc, unpack and symlink it into `~/dev/miniupnpc/`.
Finally, we can build i2pd with all that goodness

	git clone https://github.com/PurpleI2P/i2pd
	mkdir i2pd-mingw-64-build
	cd i2pd-mingw-64-build
	BOOST_ROOT=~/dev/boost_1_60_0 cmake -G 'Unix Makefiles' ~/dev/i2pd/build -DBUILD_TYPE=Release \
	  -DCMAKE_TOOLCHAIN_FILE=~/dev/toolchain-mingw.cmake -DWITH_AESNI=ON -DWITH_UPNP=ON -DWITH_STATIC=ON \
	  -DWITH_HARDENING=ON -DCMAKE_INSTALL_PREFIX:PATH=~/dev/i2pd-mingw-64-static \
	  -DZLIB_ROOT=~/dev/stage -DBOOST_LIBRARYDIR:PATH=~/dev/boost_1_60_0/stage-mingw-64/lib \
	  -DOPENSSL_ROOT_DIR:PATH=~/dev/stage
	make
	x86_64-w64-mingw32-strip i2pd.exe

By now, you should have a release build with stripped symbols.
