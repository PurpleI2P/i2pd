Building
========

On Ubuntu/Debian based
* sudo apt-get install libboost-dev libboost-filesystem-dev libboost-program-options-dev libboost-regex-dev libcrypto++-dev libboost-date-time-dev

On Arch Linux
* sudo pacman -Syu cmake boost crypto++

Then, build:

$ cd i2pd/build && cmake ../ && make

Then, run it:

$ ./i2pd

The client should now reseed by itself.

By default, the web console is located at http://localhost:7070/.

For a list of cmake options, see BUILD_NOTES.md

Installing the webui
====================

If you build from source the webui files will automatically be copied to your
 i2pd data path.
In some cases (such as when using binaries), you may have to manually install the
 webui.
For this, run:

$ ./i2pd --install=/path/to/webui

Or, if the current directory contains a folder named "webui":

$ ./i2pd --install

Building Unit Tests
===================

To build unit tests, you'll need to install the boost unit test framework.

On Ubuntu/Debian based
 * sudo apt-get install libboost-test-dev

To build the tests, run

$ cmake .. -DWITH_TESTS=ON

CMake Options
============
Available cmake options:

* CMAKE_BUILD_TYPE -- build profile (Debug/Release)
* WITH_AESNI -- AES-NI support (ON/OFF)
* WITH_HARDENING -- enable hardening features (ON/OFF) (gcc only)
* WITH_TESTS -- build tests (ON/OFF)
* WITH_BENCHMARK -- build bechmarking code (ON/OFF)
* WITH_OPTIMIZE -- enable optimization flags (ON/OFF) (not for MSVC)
* I2PD_DATA_DIR -- directory where i2pd will store data
