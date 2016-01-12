Building on Windows
=========================

There are two approaches available to build i2pd on Windows. The best
one depends on your needs and personal preferences. One is to use
msys2 and [unix alike infrastructure](build_notes_unix.md). Another
one is to use Visual Studio. While there might be no difference for
end users of i2pd daemon, developers, however, shall be wary of
differences in C++ name mangling between the two compilers when making
a choice to be able to link their software against libi2pd.

If you are a stranger to C++ with no development tools installed on
your system and your only goal is to have i2pd up and running from the
most recent source, consider using msys2. Although it relies on
command line operations, it should be straight forward.

In this guide, we will use CMake for both approaches and we will
assume that you typically have your projects in C:\dev\ as your
development location for the sake of convenience. Adjust paths
accordingly if it is not the case. Note that msys uses unix-alike
paths like /c/dev/ for C:\dev\.

msys2
-----

Get it from https://msys2.github.io and update it as described
there. Use the installer appropriate for the bitness of your Windows
OS. You will be able to build 32-bit applications if you install
64-bit version of msys2. For 64-bit, use *mingw-w64-x86_64* prefix
instead of *mingw-w64-i686* for the packages mentioned below, and use
*/mingw64* as CMake find root.

Install all prerequisites and download i2pd source:

```bash
pacman -S mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-gcc mingw-w64-i686-miniupnpc cmake git
mkdir -p /c/dev/i2pd
cd /c/dev/i2pd
git clone https://github.com/PurpleI2P/i2pd.git
cd i2pd
```

Check with `git status` that you are on *openssl* branch. If it is not
the case, do `git checkout openssl`.

```sh
git pull origin openssl --ff-only # to update sources if you are rebuilding after a while
mkdir -p mingw32.build            # CMake build folder
cd mingw32.build
export PATH=/mingw32/bin:/usr/bin # we need compiler on PATH which is usually heavily cluttered on Windows
cmake ../build -G "Unix Makefiles" -DWITH_UPNP=ON -DWITH_PCH=ON \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX:PATH=../mingw32.stage -DCMAKE_FIND_ROOT_PATH=/mingw32
```

If your processor has
[AES instruction set](https://en.wikipedia.org/wiki/AES_instruction_set),
you may try adding `-DWITH_AESNI=ON`. No check is done however, it
will compile but will crash with `Illegal instruction` if not supported.

Make sure CMake found proper libraries and compiler. This might be the
case if you have Strawberry Perl installed as it alters PATH and you
failed to override it like mentioned above. You should see something
like

```
-- The C compiler identification is GNU 5.2.0
-- The CXX compiler identification is GNU 5.2.0
-- Check for working C compiler: /mingw32/bin/gcc.exe
-- Check for working C compiler: /mingw32/bin/gcc.exe -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /mingw32/bin/c++.exe
-- Check for working CXX compiler: /mingw32/bin/c++.exe -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Performing Test CXX11_SUPPORTED
-- Performing Test CXX11_SUPPORTED - Success
-- Performing Test CXX0X_SUPPORTED
-- Performing Test CXX0X_SUPPORTED - Success
-- Looking for include file pthread.h
-- Looking for include file pthread.h - found
-- Looking for pthread_create
-- Looking for pthread_create - found
-- Found Threads: TRUE
-- Boost version: 1.59.0
-- Found the following Boost libraries:
--   system
--   filesystem
--   regex
--   program_options
--   date_time
--   thread
--   chrono
-- Found OpenSSL: /mingw32/lib/libssl.dll.a;/mingw32/lib/libcrypto.dll.a (found version "1.0.2d")
-- Found MiniUPnP headers: /mingw32/include
-- Found ZLIB: /mingw32/lib/libz.dll.a (found version "1.2.8")
-- ---------------------------------------
-- Build type         : RelWithDebInfo
-- Compiler vendor    : GNU
-- Compiler version   : 5.2.0
-- Compiler path      : /mingw32/bin/c++.exe
-- Install prefix:    : ../mingw32.stage
-- Options:
--   AESNI            : OFF
--   HARDENING        : OFF
--   LIBRARY          : ON
--   BINARY           : ON
--   STATIC BUILD     : OFF
--   UPnP             : ON
--   PCH              : ON
-- ---------------------------------------
-- Configuring done
-- Generating done
-- Build files have been written to: /c/dev/i2pd/i2pd/mingw32.build
```

Now it is time to compile everything. If you have a multicore processor
you can add `-j` flag.

    make -j4 install

You should be able to run ./i2pd . If you need to start from the new
shell, consider starting *MinGW-w64 Win32 Shell* instead of *MSYS2 Shell* as
it adds`/minw32/bin` to the PATH.

### Caveats

It is important to restrict PATH as described above. If you have
Strawberry Perl and/or Mercurial installed, it will pick up gcc &
openssl from the wrong places.

If you do use precompiled headers to speed up compilation
(recommended), things can go wrong if compiler options have changed
for whatever reason. Just delete `stdafx.h.gch` found in your build
folder, note the file extension.

If you are an Arch Linux user, refrain from updating system with
`pacman -Syu`. Always update runtime separately as described on the
home page, otherwise you might end up with DLLs incompatibility
problems.


Using Visual Studio
-------------------

Requirements for building:

* [CMake](https://cmake.org/) (tested with 3.1.3)
* [Visual Studio Community Edition](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx) (tested with VS2013 Update 4)
* [Boost](http://www.boost.org/) (tested with 1.59)
* Optionally [MiniUPnP](http://miniupnp.free.f) (tested with 1.9), we need only few client headers
* OpenSSL (tested with 1.0.1p and 1.0.2e), if building from sources (recommended), you'll need as well
	* [Netwide assembler](www.nasm.us)
	* Strawberry Perl or ActiveState Perl, do NOT try msys2 perl, it won't work


## Building Boost

Open a Command Prompt (there is no need to start Visual Studio command
prompt to build Boost) and run the following:

	cd C:\dev\boost
	bootstrap
	b2 toolset=msvc-12.0 --build-type=complete --with-filesystem --with-program_options --with-regex --with-date_time

If you are on 64-bit Windows and you want to build 64-bit version as well

	b2 toolset=msvc-12.0 --build-type=complete --stagedir=stage64 address-model=64 --with-filesystem --with-program_options --with-regex --with-date_time

After Boost is compiled, set the environment variable `BOOST_ROOT` to
the directory Boost was unpacked to, e.g., C:\dev\boost.

If you are planning on building only particular variant, e.g. Debug
only and static linking, and/or you are out of space/time, you might
consider `--build-type=minimal`. Take a look at
[appveyor.yml](../appveyor.yml) for details on how test builds are done.

Building OpenSSL
-----------------

Download OpenSSL, e.g. with git

	git clone https://github.com/openssl/openssl.git
	cd openssl
	git checkout OpenSSL_1_0_1p

Now open Visual Studio command prompt and change directory to that with OpenSSL

	set "PATH=%PATH%;C:\Program Files (x86)\nasm"
	perl Configure VC-WIN32 --prefix=c:\OpenSSL-Win32
	ms\do_nasm
	nmake -f ms\ntdll.mak
	nmake -f ms\ntdll.mak install

You should have it installed into C:\OpenSSL-Win32 by now.

Note that you might consider providing `-DOPENSSL_ROOT_DIR` to CMake
and/or create a symlink (with mklink /J) to C:\OpenSSL if you plan on
maintaining multiple versions, e.g. 64 bit and/or
static/shared. Consult `C:\Program Files
(x86)\CMake\share\cmake-3.3\Modules\FindOpenSSL.cmake` for details.

Get miniupnpc
-------------

If you are behind a UPnP enabled router and don't feel like manually
configuring port forwarding, you should consider using
[MiniUPnP](http://miniupnp.free.fr) client. I2pd can be built capable
of using miniupnpc shared library (DLL) to open up necessary
port. You'd want to have include headers around to build i2pd with
support for this. Unpack client source code in a sibling folder,
e.g. C:\dev\miniupnpc . You may want to remove version number from
folder name included in downloaded archive.

Note that you might need to build DLL yourself for 64-bit systems
using msys2 as 64-bit DLLs are not provided by the project.


Creating Visual Studio project
------------------------------

Start CMake GUI, navigate to i2pd directory, choose building directory,  e.g. ./out, and configure options.

Alternatively, if you feel adventurous, try that from the command line

```
cd <i2pd_dir>
mkdir out
cd out
cmake ..\build -G "Visual Studio 12 2013" -DWITH_UPNP=ON -DWITH_PCH=ON -DCMAKE_INSTALL_PREFIX:PATH=C:\dev\Debug_Win32_stage
```

WITH_UPNP will stay off, if necessary files are not found.

Building i2pd
-------------

You can open generated solution/project with Visual Studio and build
from there, alternatively you can use `cmake --build . --config Release --target install` or
[MSBuild tool](https://msdn.microsoft.com/en-us/library/dd293626.aspx)
`msbuild i2pd.sln /p:Configuration=Release`.
