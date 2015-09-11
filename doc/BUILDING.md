Building
========

On Ubuntu/Debian based
* sudo apt-get install libboost-dev libboost-filesystem-dev libboost-program-options-dev libboost-regex-dev libcrypto++-dev libboost-date-time-dev
* $ cd i2pd/build
* $ cmake ..
* $ make

Then, run it:

$ ./i2pd

The client should now reseed by itself.

By default, the web console is located at http://localhost:7070/.

For a list of cmake options, see build/BUILD_NOTES.md

Building Unit Tests
===================

To build unit tests, you'll need to install the boost unit test framework.

On Ubuntu/Debian based
 * sudo apt-get install libboost-test-dev

To build the tests, run

$ cmake .. -DWITH_TESTS=ON
