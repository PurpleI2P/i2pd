i2pd configuration
==================

Command line options
--------------------

Options specified on the command line take precedence over those in the config file.
If you are upgrading your very old router (< 2.3.0) see also [this](config_opts_after_2.3.0.md) page.

* --help                - Show builtin help message (default value of option will be shown in braces)
* --conf=               - Config file (default: ~/.i2pd/i2pd.conf or /var/lib/i2pd/i2pd.conf)
                          This parameter will be silently ignored if the specified config file does not exist.
* --tunconf=            - Tunnels config file (default: ~/.i2pd/tunnels.conf or /var/lib/i2pd/tunnels.conf)
* --pidfile=            - Where to write pidfile (dont write by default)
* --log=                - Logs destination: stdout, file (stdout if not set, file - otherwise, for compatibility)
* --logfile=            - Path to logfile (default - autodetect)
* --loglevel=           - Log messages above this level (debug, info, warn, error)
* --datadir=            - Path to storage of i2pd data (RI, keys, peer profiles, ...)
* --host=               - Router external IP for incoming connections
* --port=               - Port to listen for incoming connections (default: auto)
* --daemon              - Router will go to background after start
* --service             - Router will use system folders like '/var/lib/i2pd'
* --ipv6                - Enable communication through ipv6. false by default
* --notransit           - Router will not accept transit tunnels at startup. false by default
* --floodfill           - Router will be floodfill. false by default
* --bandwidth=          - Bandwidth limit: integer in KBps or letters: L (32), O (256), P (2048), X (>9000)
* --family=             - Name of a family, router belongs to

Windows-specific options:

* --svcctl=             - Windows service management (--svcctl="install" or --svcctl="remove")
* --insomnia            - Prevent system from sleeping
* --close=              - Action on close: minimize, exit, ask

All options below still possible in cmdline, but better write it in config file:

* --http.address=       - The address to listen on (HTTP server)
* --http.port=          - The port to listen on (HTTP server)
* --http.auth           - Enable basic HTTP auth for webconsole
* --http.user=          - Username for basic auth (default: i2pd)
* --http.pass=          - Password for basic auth (default: random, see logs)

* --httpproxy.address=  - The address to listen on (HTTP Proxy)
* --httpproxy.port=     - The port to listen on (HTTP Proxy) 4444 by default
* --httpproxy.keys=     - optional keys file for proxy local destination (both HTTP and SOCKS)
* --httpproxy.enabled=  - If HTTP proxy is enabled. true by default 

* --socksproxy.address= - The address to listen on (SOCKS Proxy)
* --socksproxy.port=    - The port to listen on (SOCKS Proxy). 4447 by default
* --socksproxy.keys=    - optional keys file for proxy local destination (both HTTP and SOCKS)
* --socksproxy.enabled=  - If SOCKS proxy is enabled. true by default 
* --socksproxy.outproxy= - Address of outproxy. requests outside i2p will go there
* --socksproxy.outproxyport=  - Outproxy remote port

* --sam.address=        - The address to listen on (SAM bridge)
* --sam.port=           - Port of SAM bridge. Usually 7656. SAM is off if not specified
* --sam.enabled=        - If SAM is enabled. false by default 

* --bob.address=        - The address to listen on (BOB command channel)
* --bob.port=           - Port of BOB command channel. Usually 2827. BOB is off if not specified
* --bob.enabled=        - If BOB is enabled. false by default 

* --i2cp.address=        - The address to listen on or an abstract address for Android LocalSocket
* --i2cp.port=           - Port of I2CP server. Usually 7654. Ignored for Andorid
* --i2cp.enabled=        - If I2CP is enabled. false by default. Other services don't require I2CP 

* --i2pcontrol.address= - The address to listen on (I2P control service)
* --i2pcontrol.port=    - Port of I2P control service. Usually 7650. I2PControl is off if not specified
* --i2pcontrol.enabled= - If I2P control is enabled. false by default   

* --upnp.enabled=       - Enable or disable UPnP, false by default for CLI and true for GUI (Windows, Android)  
* --upnp.name=          - Name i2pd appears in UPnP forwardings list. I2Pd by default  

* --precomputation.elgamal=  - Use ElGamal precomputated tables. false for x64 and true for other platforms by default  
* --reseed.verify=      - Request SU3 signature verification  
* --reseed.file=        - Full path to SU3 file to reseed from  
* --reseed.urls=        - Reseed URLs, separated by comma

* --limits.transittunnels=  - Override maximum number of transit tunnels. 2500 by default   

Config files
------------

INI-like, syntax is the following : <key> = <value>.
Comments are "#", not ";" as you may expect. See [boost ticket](https://svn.boost.org/trac/boost/ticket/808)
All command-line parameters are allowed as keys, but note for those which contains dot (.).

For example:

i2pd.conf:

    # comment
    log = true
    ipv6 = true
    # settings for specific module
    [httpproxy]
    port = 4444
    # ^^ this will be --httproxy.port= in cmdline
    # another comment
    [sam]
    enabled = true

See also commented config with examples of all options in ``docs/i2pd.conf``.

tunnels.conf:

    # outgoing tunnel sample, to remote service
    # mandatory parameters:
    # * type -- always "client"
    # * port -- local port to listen to
    # * destination -- i2p hostname
    # optional parameters (may be omitted)
    # * keys -- our identity, if unset, will be generated on every startup,
    #     if set and file missing, keys will be generated and placed to this file
    # * address -- local interface to bind
    # * signaturetype -- signature type for new destination. 0 (DSA/SHA1), 1 (EcDSA/SHA256) or 7 (EdDSA/SHA512)
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
    #
    [IRC-SERVER]
    type = server
    host = 127.0.0.1
    port = 6667
    keys = irc.dat

Also see [this page](https://github.com/PurpleI2P/i2pd/wiki/tunnels.cfg) for more tunnel examples.
