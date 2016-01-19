i2pd configuration
==================

Command line options
--------------------

* --host=               - The external IP (deprecated). 
* --port=               - The port to listen on
* --httpaddress=        - The address to listen on (HTTP server)
* --httpport=           - The port to listen on (HTTP server)
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --loglevel=           - Log messages above this level (debug, *info, warn, error)
* --pidfile=            - Where to write pidfile (dont write by default)
* --daemon=             - Enable or disable daemon mode. 1 for yes, 0 for no.
* --svcctl=             - Windows service management (--svcctl="install" or --svcctl="remove")
* --service=            - 1 if uses system folders (/var/run/i2pd.pid, /var/log/i2pd.log, /var/lib/i2pd).
* --v6=                 - 1 if supports communication through ipv6, off by default
* --floodfill=          - 1 if router is floodfill, off by default
* --bandwidth=          - L if bandwidth is limited to 32Kbs/sec, O - to 256Kbs/sec, P - unlimited
* --notransit=          - 1 if router doesn't accept transit tunnels at startup. 0 by default
* --httpproxyaddress=   - The address to listen on (HTTP Proxy)
* --httpproxyport=      - The port to listen on (HTTP Proxy) 4446 by default
* --socksproxyaddress=  - The address to listen on (SOCKS Proxy)
* --socksproxyport=     - The port to listen on (SOCKS Proxy). 4447 by default
* --proxykeys=          - optional keys file for proxy local destination (both HTTP and SOCKS)
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
Comments are "#", not ";" as you may expect. See [boost ticket](https://svn.boost.org/trac/boost/ticket/808)
All command-line parameters are allowed as keys, for example:

i2p.conf:

    log = 1
    v6 = 0

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
    # * type -- always "server"
    # * host -- ip address of our service
    # * port -- port of our service
    # * keys -- file with LeaseSet of address in i2p
    # optional parameters (may be omitted)
    # * inport -- optional, i2p service port, if unset - the same as 'port'
    # * accesslist -- comma-separated list of i2p addresses, allowed to connect
    #    every address is b32 without '.b32.i2p' part
    [LOCALSITE]
    type = server
    host = 127.0.0.1
    port = 80
    keys = site-keys.dat
    inport = 81
    accesslist = <b32>[,<b32>]

Also see [this page](https://github.com/PurpleI2P/i2pd/wiki/tunnels.cfg) for more tunnel examples.
