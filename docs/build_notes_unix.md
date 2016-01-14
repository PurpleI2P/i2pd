Building on Unix systems
=============================

First of all we need to make sure that all dependencies are satisfied.

This doc is trying to cover:
* [Debian/Ubuntu](#debianubuntu) (contains packaging instructions)
* [FreeBSD](#freebsd)

Make sure you have all required dependencies for your system successfully installed.

If so then we are ready to go!
Let's clone the repository and start building the i2pd:
```bash
git clone https://github.com/PurpleI2P/i2pd.git
cd i2pd/build
cmake -DCMAKE_BUILD_TYPE=Release # more options could be passed, see "CMake Options"
make
```

After successfull build i2pd could be installed with:
```bash
make install
```

Debian/Ubuntu
-------------

You will need a compiler and other tools that could be installed with `build-essential` package:
```bash
sudo apt-get install build-essential
```

Also you will need a bunch of development libraries:
```bash
sudo apt-get install \
    libboost-chrono-dev \
    libboost-date-time-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-regex-dev \
    libboost-system-dev \
    libboost-thread-dev \
    libssl-dev
```

If you need UPnP support (don't forget to run CMake with `WITH_UPNP=ON`) miniupnpc development library should be installed:
```bash
sudo apt-get install libminiupnpc-dev
```

You may also build deb-package with the following:
```bash
sudo apt-get install fakeroot devscripts
cd i2pd
debuild --no-tgz-check
```

FreeBSD
-------

Branch 9.X has gcc v4.2, that knows nothing about required c++11 standart.

Required ports:

* `devel/cmake`
* `devel/boost-libs`
* `lang/gcc47`(or later version)

To use newer compiler you should set these variables(replace "47" with your actual gcc version):
```bash
export CC=/usr/local/bin/gcc47
export CXX=/usr/local/bin/g++47
```

Branch 10.X has more reliable clang version, that can finally build i2pd,
but I still recommend to use gcc, otherwise you will fight it's bugs by
your own.

CMake Options
-------------

Available CMake options(each option has a for of `<key>=<value>`, for more information see `man 1 cmake`):

* `CMAKE_BUILD_TYPE` build profile (Debug/Release)
* `WITH_BINARY`      build i2pd itself
* `WITH_LIBRARY`     build libi2pd
* `WITH_STATIC`      build static versions of library and i2pd binary
* `WITH_UPNP`        build with UPnP support (requires libupnp)
* `WITH_AESNI`        build with AES-NI support (ON/OFF)
* `WITH_HARDENING`   enable hardening features (ON/OFF) (gcc only)
* `WITH_PCH`         use pre-compiled header (experimental, speeds up build)

Also there is `-L` flag for CMake that could be used to list current cached options:
```bash
cmake -L
```
