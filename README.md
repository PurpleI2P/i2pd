i2pd
====

I2P router written in C++
Contains all ongoing changes from https://bitbucket.org/orignal/i2pd/src

License
-------

This project is licensed under the BSD 3-clause license, which can be found in the file
LICENSE in the root of the project source code.

Donations
---------

BTC: 1K7Ds6KUeR8ya287UC4rYTjvC96vXyZbDY   
LTC: LKQirrYrDeTuAPnpYq5y7LVKtywfkkHi59   
ANC: AQJYweYYUqM1nVfLqfoSMpUMfzxvS4Xd7z

Downloads
------------

Official binary releases could be found at:
http://i2pd.website/releases/   
older releases
http://download.i2p.io/purplei2p/i2pd/releases/


Build Statuses
---------------

- Linux x64      - [![Build Status](https://jenkins.greyhat.no/buildStatus/icon?job=i2pd-linux)](https://jenkins.nordcloud.no/job/i2pd-linux/)
- Linux ARM      - To be added
- Mac OS X       - Got it working, but not well tested. (Only works with clang, not GCC.)
- Microsoft VC13 - To be added


Testing
-------

First, build it.

On Ubuntu/Debian based
* sudo apt-get install libboost-dev libboost-filesystem-dev libboost-program-options-dev libboost-regex-dev libboost-date-time-dev libssl-dev zlib1g-dev 
* $ cd i2pd
* $ make

Then, run it:

$ ./i2p

The client should now reseed by itself.
To visit an eepsite use HTTP proxy port 4446.
For tunnels follow [instructions](https://github.com/PurpleI2P/i2pd/wiki/tunnels.cfg)


Cmdline options
---------------

* --host=               - The external IP (deprecated). 
* --port=               - The port to listen on
* --httpaddress=        - The address to listen on (HTTP server)
* --httpport=           - The port to listen on (HTTP server)
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --daemon=             - Enable or disable daemon mode. 1 for yes, 0 for no.
* --service=            - 1 if uses system folders (/var/run/i2pd.pid, /var/log/i2pd.log, /var/lib/i2pd).
* --v6=                 - 1 if supports communication through ipv6, off by default
* --floodfill=          - 1 if router is floodfill, off by default
* --bandwidth=          - L if bandwidth is limited to 32Kbs/sec, O if not. Always O if floodfill, otherwise L by default.
* --httpproxyaddress=   - The address to listen on (HTTP Proxy)
* --httpproxyport=      - The port to listen on (HTTP Proxy) 4446 by default
* --socksproxyaddress=  - The address to listen on (SOCKS Proxy)
* --socksproxyport=     - The port to listen on (SOCKS Proxy). 4447 by default
* --proxykeys=          - optional keys file for proxy's local destination
* --ircaddress=         - The address to listen on (IRC tunnel)
* --ircport=            - The port listen on (IRC tunnel). 6668 by default
* --ircdest=            - I2P destination address of IRC server. For example irc.postman.i2p
* --irckeys=            - optional keys file for tunnel's local destination 
* --eepkeys=            - File name containing destination keys, for example privKeys.dat.
                          The file will be created if it does not already exist (issue #110).
* --eephost=            - Address incoming trafic forward to. 127.0.0.1 by default
* --eepport=            - Port incoming trafic forward to. 80 by default
* --samaddress=         - The address to listen on (SAM bridge)
* --samport=            - Port of SAM bridge. Usually 7656. SAM is off if not specified
* --bobaddress=         - The address to listen on (BOB command channel)
* --bobport=            - Port of BOB command channel. Usually 2827. BOB is off if not specified
* --i2pcontroladdress=  - The address to listen on (I2P control service)
* --i2pcontrolport=     - Port of I2P control service. Usually 7650. I2PControl is off if not specified
* --tunnelscfg=         - Tunnels Config file (default: ~/.i2pd/tunnels.cfg or /var/lib/i2pd/tunnels.cfg)
* --conf=               - Config file (default: ~/.i2pd/i2p.conf or /var/lib/i2pd/i2p.conf)
                          This parameter will be silently ignored if the specified config file does not exist.
                          Options specified on the command line take precedence over those in the config file.

Config files
------------

INI-like, syntax is the following : <key> = <value>.
All command-line parameters are allowed as keys, for example:

i2p.conf:

	log = 1
	v6 = 0
	ircdest = irc.postman.i2p

tunnels.cfg (filename of this config is subject of change):

  ; outgoing tunnel sample, to remote service   
  ; mandatory parameters:   
  ; * type -- always "client"  
  ; * port -- local port to listen to   
  ; * destination -- i2p hostname   
  ; optional parameters (may be omitted)   
  ; * keys -- our identity, if unset, will be generated on every startup,   
  ;     if set and file missing, keys will be generated and placed to this file   
	[IRC]   
	type = client   
	port = 6668   
	destination = irc.echelon.i2p   
	keys = irc-keys.dat   
   
  ; incoming tunnel sample, for local service   
  ; mandatory parameters:   
  ; * type -- always "server"   
  ; * host -- ip address of our service   
  ; * port -- port of our service   
  ; * keys -- file with LeaseSet of address in i2p   
  ; optional parameters (may be omitted)   
  ; * inport -- optional, i2p service port, if unset - the same as 'port'   
  ; * accesslist -- comma-separated list of i2p addresses, allowed to connect   
  ;    every address is b32 without '.b32.i2p' part   
	[LOCALSITE]   
	type = server   
	host = 127.0.0.1   
	port = 80   
	keys = site-keys.dat   
	inport = 81   
	accesslist = <b32>[,<b32>]   
