Requirements
============

Linux/FreeBSD/OSX
-----------------

GCC 4.6 or newer, Boost 1.46 or newer, openssl, zlib. Clang can be used instead of GCC.

Windows
-------

VS2013 (known to work with 12.0.21005.1 or newer), Boost 1.46 or newer,
crypto++ 5.62. See Win32/README-Build.txt for instructions on how to build i2pd
and its dependencies.

Build notes
===========

Common build/install process:

* git clone https://github.com/PurpleI2P/i2pd.git
* cd i2pd/build
* cmake -DCMAKE_BUILD_TYPE=Release <more options> .
* make
* make install

Available cmake options:

* CMAKE_BUILD_TYPE -- build profile (Debug/Release)
* WITH_AESNI -- AES-NI support (ON/OFF)
* WITH_HARDENING -- enable hardening features (ON/OFF) (gcc only)

Debian
------

Required "-dev" packages:

* libboost-filesystem-dev
* libboost-program-options-dev
* libboost-regex-dev
* libboost-system-dev
* libboost-date-time-dev
* libssl-dev

FreeBSD
-------

Branch 9.X has gcc v4.2, that knows nothing about required c++11 standart.

Required ports:

* devel/cmake
* devel/boost-libs
* lang/gcc47 # or later version

To use newer compiler you should set these variables:

    export CC=/usr/local/bin/gcc47
    export CXX=/usr/local/bin/g++47

Replace "47" with your actual gcc version

Branch 10.X has more reliable clang version, that can finally build i2pd,
but i still recommend to use gcc, otherwise you will fight it's bugs by
your own.
