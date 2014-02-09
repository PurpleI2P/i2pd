i2pd
====

i2p router for Linux written on C++

Requires gcc 4.6 and higher, boost 1.46 and higher, crypto++

on Windows

Requires msvs2013, boost 1.46 and higher, crypto++


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
After that, go to the webconsole and add it behind the url. (Remove http:// and b32.i2p from the address)

This should resulting in for example:
http://localhost:7070/4oes3rlgrpbkmzv4lqcfili23h3cvpwslqcfjlk6vvguxyggspwa


Options
-------

* --host=               - The external IP
* --port=               - The port to listen on
* --httpport=           - The http port to listen on
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --daemon=             - Eanble or disable daemon mode. 1 for yes, 0 for no.



