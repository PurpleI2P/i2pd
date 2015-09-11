Cmdline options
===============

* --host=               - The external IP (deprecated).
* --port=               - The port to listen on
* --httpport=           - The http port to listen on
* --httpaddress=        - The ip address for the HTTP server, 127.0.0.1 by default
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --daemon=             - Enable or disable daemon mode. 1 for yes, 0 for no.
* --service=            - 1 if uses system folders (/var/run/i2pd.pid, /var/log/i2pd.log, /var/lib/i2pd).
* --v6=                 - 1 if supports communication through ipv6, off by default
* --floodfill=          - 1 if router is floodfill, off by default
* --bandwidth=          - L if bandwidth is limited to 32Kbs/sec, O if not. Always O if floodfill, otherwise L by default.
* --httpproxyport=      - The port to listen on (HTTP Proxy)
* --httpproxyaddress=   - The address to listen on (HTTP Proxy)
* --socksproxyport=     - The port to listen on (SOCKS Proxy)
* --socksproxyaddress=  - The address to listen on (SOCKS Proxy)
* --proxykeys=          - optional keys file for proxy's local destination
* --ircport=            - The local port of IRC tunnel to listen on. 6668 by default
* --ircaddress=         - The adddress of IRC tunnel to listen on, 127.0.0.1 by default
* --ircdest=            - I2P destination address of IRC server. For example irc.postman.i2p
* --irckeys=            - optional keys file for tunnel's local destination
* --eepkeys=            - File name containing destination keys, for example privKeys.dat.
                          The file will be created if it does not already exist (issue #110).
* --eepaddress=         - Address incoming trafic forward to. 127.0.0.1 by default
* --eepport=            - Port incoming trafic forward to. 80 by default
* --samport=            - Port of SAM bridge. Usually 7656. SAM is off if not specified
* --samaddress=         - Address of SAM bridge, 127.0.0.1 by default (only used if SAM is on)
* --bobport=            - Port of BOB command channel. Usually 2827. BOB is off if not specified
* --bobaddress=         - Address of BOB service, 127.0.0.1 by default (only used if BOB is on)
* --i2pcontrolport=     - Port of I2P control service. Usually 7650. I2PControl is off if not specified
* --i2pcontroladdress=  - Address of I2P control service, 127.0.0.1 by default (only used if I2PControl is on)
* --i2pcontrolpassword= - I2P control service password, "itoopie" by default
* --tunnelscfg=         - Tunnels Config file (default: ~/.i2pd/tunnels.cfg or /var/lib/i2pd/tunnels.cfg)
* --conf=               - Config file (default: ~/.i2pd/i2p.conf or /var/lib/i2pd/i2p.conf)
                          This parameter will be silently ignored if the specified config file does not exist.
                          Options specified on the command line take precedence over those in the config file.
