i2pd
====

I2P router written in C++

License
-------

This project is licensed under the BSD 3-clause license, which can be found in the file
LICENSE in the root of the project source code.

Requirements for Linux/FreeBSD/OSX
----------------------------------

GCC 4.6 or newer, Boost 1.46 or newer, crypto++. Clang can be used instead of
GCC.

Requirements for Windows
------------------------

VS2013 (known to work with 12.0.21005.1 or newer), Boost 1.46 or newer,
crypto++ 5.62. See Win32/README-Build.txt for instructions on how to build i2pd
and its dependencies.

Downloads
------------

Official binary releases could be found at:
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
* sudo apt-get install libboost-dev libboost-filesystem-dev libboost-program-options-dev libboost-regex-dev libcrypto++-dev libboost-date-time-dev
* $ cd i2pd
* $ make

Then, run it:

$ ./i2p

The client should now reseed by itself.

To visit an I2P page, you need to find the b32 address of your destination.
After that, go to the webconsole and add it behind the url. (Remove http:// from the address)

This should resulting in for example:
http://localhost:7070/4oes3rlgrpbkmzv4lqcfili23h3cvpwslqcfjlk6vvguxyggspwa.b32.i2p


Cmdline options
---------------

* --host=               - The external IP
* --port=               - The port to listen on
* --httpport=           - The http port to listen on
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --daemon=             - Enable or disable daemon mode. 1 for yes, 0 for no.
* --service=            - 1 if uses system folders (/var/run/i2pd.pid, /var/log/i2pd.log, /var/lib/i2pd).
* --v6=                 - 1 if supports communication through ipv6, off by default
* --floodfill=          - 1 if router is floodfill, off by default
* --bandwidth=          - L if bandwidth is limited to 32Kbs/sec, O if not. Always O if floodfill, otherwise L by default.
* --httpproxyport=      - The port to listen on (HTTP Proxy)
* --socksproxyport=     - The port to listen on (SOCKS Proxy)
* --proxykeys=          - optional keys file for proxy's local destination
* --ircport=            - The local port of IRC tunnel to listen on. 6668 by default
* --ircdest=            - I2P destination address of IRC server. For example irc.postman.i2p
* --irckeys=            - optional keys file for tunnel's local destination 
* --eepkeys=            - File name containing destination keys, for example privKeys.dat.
                          The file will be created if it does not already exist (issue #110).
* --eephost=            - Address incoming trafic forward to. 127.0.0.1 by default
* --eepport=            - Port incoming trafic forward to. 80 by default
* --samport=            - Port of SAM bridge. Usually 7656. SAM is off if not specified
* --bobport=            - Port of BOB command channel. Usually 2827. BOB is off if not specified
* --i2pcontrolport=     - Port of I2P control service. Usually 7650. I2PControl is off if not specified
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

   ; outgoing tunnel, to remote service    
  [tunnel1]  
  type = client      ; mandatory   
  port = <integer>   ; mandatory, bind our side of tunnel to this local port  
  keys = <filename>  ; optional  
  destination     = <ident>    ; mandatory  
  destinationport = <integer>  ; optional, port of remote i2p service  
     
   ; incoming tunnel, for local service(s)   
  [tunnel2]   
  type = server      ; mandatory   
  host = <ident>     ; mandatory, hostname of our i2p service   
  keys = <filename>  ; mandatory, hostname keys   
  port = <integer>   ; mandatory, forward incoming connections from i2p to this port      
  inport = <integer> ; optional, i2p service port   
  accesslist = <ident>[,<ident>] ; optional, comma-separated list of i2p idents, allowed to connect to service  

Note: '<ident>' type is a string like <hostname.i2p> or <abracadabra.b32.i2p>  
