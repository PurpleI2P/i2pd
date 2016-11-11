Building on Windows
=========================

There are two approaches available to build i2pd on Windows. The best
one depends on your needs and personal preferences. One is to use
msys2 and [unix alike infrastructure](unix.md). Another
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

Get install file `msys2-$ARCH-*.exe` from `https://msys2.github.io`

Where $ARCH is `i686` or `x86_64` (matching your system).

- Open MSYS2 Shell (from Start menu).
- Install all prerequisites and download i2pd source:

        export ARCH='i686'     # or 'x86_64'
        export MINGW='mingw32' # or 'mingw64'
        pacman -S mingw-w64-$ARCH-boost mingw-w64-$ARCH-openssl mingw-w64-$ARCH-gcc git make
        mkdir -p /c/dev/i2pd
        cd /c/dev/i2pd
        git clone https://github.com/PurpleI2P/i2pd.git
        cd i2pd
        # we need compiler on PATH which is usually heavily cluttered on Windows
        export PATH=/$MINGW/bin:/usr/bin
        make

### Caveats

It is important to restrict PATH as described above.
If you have Strawberry Perl and/or Mercurial installed,
it will pick up gcc & openssl from the wrong places.

If you do use precompiled headers to speed up compilation (recommended),
things can go wrong if compiler options have changed for whatever reason.
Just delete `stdafx.h.gch` found in your build folder, note the file extension.

If you are an Arch Linux user, refrain from updating system with `pacman -Syu`.
Always update runtime separately as described on the home page,
otherwise you might end up with DLLs incompatibility problems.

### AES-NI

If your processor has [AES instruction set](https://en.wikipedia.org/wiki/AES_instruction_set),
use `make USE_AESNI=1` instead just `make`. No check is done however, it will compile,
but it might crash with `Illegal instruction` if this feature is not supported by your processor.

You should be able to run ./i2pd . If you need to start from the new shell,
consider starting *MinGW-w64 Win32 Shell* instead of *MSYS2 Shell*
as it adds `/minw32/bin` to the PATH.

### UPnP

You can install it through the MSYS2 and build with `USE_UPNP` key.

	export ARCH='i686' # or 'x86_64'
	pacman -S mingw-w64-$ARCH-miniupnpc
	make USE_UPNP=yes

Using Visual Studio
-------------------

Requirements for building:

* [CMake](https://cmake.org/) (tested with 3.1.3)
* [Visual Studio Community Edition](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx) (tested with VS2013 Update 4)
* [Boost](http://www.boost.org/) (tested with 1.59)
* Optionally [MiniUPnP](http://miniupnp.free.fr) (tested with 1.9), we need only few client headers
* OpenSSL (tested with 1.0.1p and 1.0.2e), if building from sources (recommended), you'll need as well
	* [Netwide assembler](http://www.nasm.us/)
	* Strawberry Perl or ActiveState Perl, do NOT try msys2 perl, it won't work

### Building Boost

Open a Command Prompt (there is no need to start Visual Studio command
prompt to build Boost) and run the following:

	cd C:\dev\boost
	bootstrap
	b2 toolset=msvc-12.0 --build-type=complete --with-filesystem --with-program_options --with-date_time

If you are on 64-bit Windows and you want to build 64-bit version as well

	b2 toolset=msvc-12.0 --build-type=complete --stagedir=stage64 address-model=64 --with-filesystem --with-program_options --with-date_time

After Boost is compiled, set the environment variable `BOOST_ROOT` to
the directory Boost was unpacked to, e.g., C:\dev\boost.

If you are planning on building only particular variant, e.g. Debug only and static linking,
and/or you are out of space/time, you might consider `--build-type=minimal`.
Take a look at [appveyor.yml](../appveyor.yml) for details on how test builds are done.

### Building OpenSSL

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

Note that you might consider providing `-DOPENSSL_ROOT_DIR` to CMake and/or
create a symlink (with mklink /J) to C:\OpenSSL if you plan on maintain
multiple versions, e.g. 64 bit and/or static/shared.
See `C:\Program Files (x86)\CMake\share\cmake-3.3\Modules\FindOpenSSL.cmake` for details.

### Get miniupnpc

If you are behind a UPnP enabled router and don't feel like manually configuring port forwarding,
you should consider using [MiniUPnP](http://miniupnp.free.fr) client.
I2pd can be built capable of using miniupnpc shared library (DLL) to open up necessary port.
You'd want to have include headers around to build i2pd with support for this.
Unpack client source code to subdir, e.g. `C:\dev\miniupnpc`.
You may want to remove version number from folder name included in downloaded archive.
 
### Creating Visual Studio project

Start CMake GUI, navigate to i2pd directory, choose building directory,  e.g. ./out, and configure options.

Alternatively, if you feel adventurous, try that from the command line

	mkdir i2pd\out
	cd i2pd\out
	cmake ..\build -G "Visual Studio 12 2013" -DWITH_UPNP=ON -DWITH_PCH=ON -DCMAKE_INSTALL_PREFIX:PATH=C:\dev\Debug_Win32_stage

If necessary files are not found `WITH_UPNP` will stay off.

### Building i2pd

You can open generated solution/project with Visual Studio and build from there,
alternatively you can use `cmake --build . --config Release --target install` or
[MSBuild tool](https://msdn.microsoft.com/en-us/library/dd293626.aspx)

	msbuild i2pd.sln /p:Configuration=Release
