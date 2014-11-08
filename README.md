i2pd
====

I2P router written in C++

Requirements for Linux/FreeBSD/OSX
----------------------------------

GCC 4.6 or newer, Boost 1.46 or newer, crypto++. Clang can be used instead of
GCC.

Requirements for Windows
------------------------

VS2013 (known to work with 12.0.21005.1 or newer), Boost 1.46 or newer,
crypto++ 5.62. See Win32/README-Build.txt for instructions on how to build i2pd
and its dependencies.

Build Statuses
---------------

- Linux x64      - [![Build Status](https://jenkins.nordcloud.no/buildStatus/icon?job=i2pd-linux)](https://jenkins.nordcloud.no/job/i2pd-linux/)
- Linux ARM      - To be added
- Mac OS X       - To be added
- Microsoft VC13 - To be added


Testing
-------

First, build it.

* $ cd i2pd
* $ make

Next, find out your public ip. (find it for example at http://www.whatismyip.com/)

Then, run it with:

$ ./i2p --host=YOUR_PUBLIC_IP

The client should now reseed by itself.

To visit an I2P page, you need to find the b32 address of your destination.
After that, go to the webconsole and add it behind the url. (Remove http:// from the address)

This should resulting in for example:
http://localhost:7070/4oes3rlgrpbkmzv4lqcfili23h3cvpwslqcfjlk6vvguxyggspwa.b32.i2p


Options
-------

* --host=               - The external IP
* --port=               - The port to listen on
* --httpport=           - The http port to listen on
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --daemon=             - Enable or disable daemon mode. 1 for yes, 0 for no.
* --service=            - 1 if uses system folders (/var/run/i2pd.pid, /var/log/i2pd.log, /var/lib/i2pd).
* --unreachable=        - 1 if router is declared as unreachable and works through introducers.
* --v6=                 - 1 if supports communication through ipv6, off by default
* --httpproxyport=      - The port to listen on (HTTP Proxy)
* --socksproxyport=     - The port to listen on (SOCKS Proxy)
* --ircport=            - The local port of IRC tunnel to listen on. 6668 by default
* --ircdest=            - I2P destination address of IRC server. For example irc.postman.i2p
* --irckeys=            - optional keys file for local destination
* --eepkeys=            - File name containing destination keys. For example privKeys.dat
* --eephost=            - Address incoming trafic forward to. 127.0.0.1 by default
* --eepport=            - Port incoming trafic forward to. 80 by default
* --samport=            - Port of SAM bridge. Usually 7656. SAM is off if not specified

