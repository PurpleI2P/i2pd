i2pd configuration
==================

Command line options
--------------------

* --conf=               - Config file (default: ~/.i2pd/i2p.conf or /var/lib/i2pd/i2p.conf)
                          This parameter will be silently ignored if the specified config file does not exist.
                          Options specified on the command line take precedence over those in the config file.
* --tunconf=            - Tunnels config file (default: ~/.i2pd/tunnels.cfg or /var/lib/i2pd/tunnels.cfg)
* --pidfile=            - Where to write pidfile (dont write by default)
* --log=                - Logs destination: stdout, file (stdout if not set, file - otherwise, for compatibility)
* --logfile=            - Path to logfile (default - autodetect)
* --loglevel=           - Log messages above this level (debug, *info, warn, error)
* --datadir=            - Path to storage of i2pd data (RI, keys, peer profiles, ...)
* --host=               - The external IP
* --port=               - The port to listen on
* --daemon              - Router will go to background after start
* --service             - Router will use system folders like '/var/lib/i2pd'
* --ipv6                - Enable communication through ipv6
* --notransit           - Router will not accept transit tunnels at startup
* --floodfill           - Router will be floodfill
* --bandwidth=          - L if bandwidth is limited to 32Kbs/sec, O - to 256Kbs/sec, P - unlimited
* --family=             - Name of a family, router belongs to
* --svcctl=             - Windows service management (--svcctl="install" or --svcctl="remove")

* --http.address=       - The address to listen on (HTTP server)
* --http.port=          - The port to listen on (HTTP server)

* --httpproxy.address=  - The address to listen on (HTTP Proxy)
* --httpproxy.port=     - The port to listen on (HTTP Proxy) 4446 by default
* --httpproxy.keys=     - optional keys file for proxy local destination (both HTTP and SOCKS)

* --socksproxy.address= - The address to listen on (SOCKS Proxy)
* --socksproxy.port=    - The port to listen on (SOCKS Proxy). 4447 by default
* --socksproxy.keys=    - optional keys file for proxy local destination (both HTTP and SOCKS)
* --socksproxy.outproxy=      - Address of outproxy. requests outside i2p will go there
* --socksproxy.outproxyport=  - Outproxy remote port

* --sam.address=        - The address to listen on (SAM bridge)
* --sam.port=           - Port of SAM bridge. Usually 7656. SAM is off if not specified

* --bob.address=        - The address to listen on (BOB command channel)
* --bob.port=           - Port of BOB command channel. Usually 2827. BOB is off if not specified

* --i2pcontrol.address= - The address to listen on (I2P control service)
* --i2pcontrol.port=    - Port of I2P control service. Usually 7650. I2PControl is off if not specified

Config files
------------

INI-like, syntax is the following : <key> = <value>.
Comments are "#", not ";" as you may expect. See [boost ticket](https://svn.boost.org/trac/boost/ticket/808)
All command-line parameters are allowed as keys, but note for those which contains dot (.).

For example:

i2p.conf:

    # comment
    log = yes
    ipv6 = yes
    # settings for specific module
    [httpproxy]
    port = 4444
    # ^^ this will be --httproxy.port= in cmdline
    # another one
    [sam]
    enabled = yes

tunnels.cfg (filename of this config is subject of change):

    # outgoing tunnel sample, to remote service
    # mandatory parameters:
    # * type -- always "client"
    # * port -- local port to listen to
    # * destination -- i2p hostname
    # optional parameters (may be omitted)
    # * keys -- our identity, if unset, will be generated on every startup,
    #     if set and file missing, keys will be generated and placed to this file
    # * address -- local interface to bind
    # * signaturetype -- signature type for new destination. 0,1 or 7
    [IRC]
    type = client
    address = 127.0.0.1
    port = 6668
    destination = irc.postman.i2p
    keys = irc-keys.dat
    #
    # incoming tunnel sample, for local service
    # mandatory parameters:
    # * type -- "server" or "http"
    # * host -- ip address of our service
    # * port -- port of our service
    # * keys -- file with LeaseSet of address in i2p
    # optional parameters (may be omitted)
    # * inport -- optional, i2p service port, if unset - the same as 'port'
    # * accesslist -- comma-separated list of i2p addresses, allowed to connect
    #    every address is b32 without '.b32.i2p' part
    [LOCALSITE]
    type = http
    host = 127.0.0.1
    port = 80
    keys = site-keys.dat
    [IRC-SERVER]
    type = server
    host = 127.0.0.1
    port = 6667
    keys = irc.dat

Also see [this page](https://github.com/PurpleI2P/i2pd/wiki/tunnels.cfg) for more tunnel examples.
