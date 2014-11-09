Building i2pd for Windows
=========================

Requirements for building:

* Visual Studio 2013 (tested with VS2013 Update 1, Update 3, and Update 4 RC)
* Boost (tested with 1.56 and 1.57)
* Crypto++ (tested with 5.6.2)


Building Boost (32-bit)
-----------------------

Open a Visual Studio x86 command prompt and run the following:

	cd C:\path\to\boost\sources
	bootstrap
	b2 toolset=msvc-12.0 --build-type=complete --libdir=C:\Boost\lib\Win32 install --with-filesystem --with-program_options --with-regex --with-date_time


Building Boost (64-bit)
-----------------------

Open a Visual Studio x64 command prompt and run the following:

	cd C:\path\to\boost\sources
	bootstrap
	b2 toolset=msvc-12.0 --build-type=complete --libdir=C:\Boost\lib\x64 architecture=x86 address-model=64 install --with-filesystem --with-program_options --with-regex --with-date_time

After Boost is compiled, set the environment variable `BOOST` to the directory
Boost was installed to. If you followed the instructions outlined here, you
should set it to `C:\Boost`. Additionally, set the BOOSTVER variable to the
version of Boost that you're using, but instead of a '.' use a '_'. For
example, I have `BOOSTVER` set to `1_57`.

Building Crypto++
-----------------

* Open the crypttest Solution in VS2013
* Visual Studio will ask to update the Solution/Project. Allow it.
* Build the `cryptopp` project, both the Debug and Release targets and for both
  Win32 and x64.
* Create a folder called `cryptopp` in the crypto++ source directory, then copy
  the header files to this new directory.
* Set the `CRYPTOPP` environment variable pointing to the Crypto++ source directory.


Building i2pd
-------------

## Prep work ##

I strongly advise setting up your own `INCLUDES` and `LIBS` instead of relying
on the settings in the i2pd project file. By using your own settings, if the
i2pd devs change the paths in the project file, your builds will still work.

To do this, create or edit the file
`%localappdata%\Microsoft\MSBuild\v4.0\Microsoft.Cpp.Win32.user`.

For comparison, my file is reproduced below:

	<?xml version="1.0" encoding="utf-8"?>
	<Project DefaultTargets="Build" ToolsVersion="12.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	  <ImportGroup Label="PropertySheets">
	  </ImportGroup>
	  <PropertyGroup Label="UserMacros" />
	  <PropertyGroup>
	    <LibraryPath>$(CRYPTOPP)\$(Platform)\Output\$(Configuration);$(BOOST)\lib\$(Platform);$(LibraryPath)</LibraryPath>
	    <IncludePath>$(CRYPTOPP);$(BOOST)\include\boost-$(BOOSTVER);$(IncludePath)</IncludePath>
	  </PropertyGroup>
	  <ItemDefinitionGroup />
	  <ItemGroup />
	</Project>


If you want to build x64 binaries as well, you'll want to edit or create the
file `%localappdata%\Microsoft\MSBuild\v4.0\Microsoft.Cpp.x64.user`. If you
followed the steps outlined earlier you can copy (or link) the win32 file to
the x64 one.

## Anti-Climatic End ##

After following the above instructions, you'll be able to build Debug Win32,
Debug x64, Release Win32, and Release x64 i2pd binaries.
