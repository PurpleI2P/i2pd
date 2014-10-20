Build notes
===========

Common build/install process:

* git clone https://github.com/PrivacySolutions/i2pd.git
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
* cmake
* libboost-filesystem-dev
* libboost-program-options-dev
* libboost-regex-dev
* libboost-system-dev
* libcrypto++-dev

FreeBSD
-------

Branch 9.X has gcc v4.2, that knows nothing about required c++11 standart.

Required ports:

* devel/cmake
* devel/boost-libs
* lang/gcc47 # or later version
* security/cryptopp

To use newer compiler you should set these variables:

  export CC=/usr/local/bin/gcc47
  export CXX=/usr/local/bin/g++47

Replace "47" with your actual gcc version

Branch 10.X has more reliable clang version, that can finally build i2pd,
but i still recommend to use gcc, otherwise you will fight it's bugs by
your own.
