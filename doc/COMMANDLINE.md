CLI Options
===========

Basic
* --host=               - The external IP (deprecated). Default: external interface.
* --port=               - The port to listen on. Default: random (then saved to router.info).
* --httpport=           - The HTTP port to listen on for WebUI. Default: 7070
* --httpaddress=        - The IP address of the WebUI HTTP server. Default: 127.0.0.1

System
* --log=                - Enable or disable logging to file. 1 for yes, 0 for no.
* --daemon=             - Enable or disable daemon mode. 1 for yes, 0 for no.
* --service=            - 1 if using system folders (/var/run/i2pd.pid, /var/log/i2pd.log, /var/lib/i2pd).

Network
* --v6=                 - 1 to enable IPv6. Default: disabled.
* --floodfill=          - 1 to enable router router as floodfill. Default: disabled.
* --bandwidth=          - L if bandwidth is limited to 32Kbs/sec, O if not. Always O if floodfill, otherwise L by default.

Proxies
* --httpproxyport=      - The HTTP Proxy port to listen on. Default: 4446
* --httpproxyaddress=   - The HTTP Proxy address to listen on. Default: 127.0.0.1
* --socksproxyport=     - The SOCKS Proxy port to listen on. Default: 4447
* --socksproxyaddress=  - The SOCKS Proxy address to listen on. Default: 127.0.0.1
* --proxykeys=          - Optional keys file for proxy's local destination

IRC
* --ircport=            - The local port of IRC tunnel to listen on. Default: 6668
* --ircaddress=         - The adddress of IRC tunnel to listen on. Default: 127.0.0.1
* --ircdest=            - I2P destination address of IRC server. For example irc.postman.i2p
* --irckeys=            - Optional keys file for tunnel's local destination.

Eepsite
* --eepkeys=            - File name containing destination keys, for example privKeys.dat.
                          The file will be created if it does not already exist (issue #110).
* --eepaddress=         - Forward incoming traffic to this address. Default: 127.0.0.1
* --eepport=            - Forward incoming traffic to this port. Default: 80

API
* --samport=            - Port of SAM bridge (usually 7656). Default: SAM is disabled if not specified.
* --samaddress=         - Address of SAM bridge. Default: 127.0.0.1 (only used if SAM is enabled).
* --bobport=            - Port of BOB command channel (usually 2827). BOB is disabled if not specified.
* --bobaddress=         - Address of BOB service. Default: 127.0.0.1 (only used if BOB is enabled).

I2CP
* --i2pcontrolport=     - Port of I2P control service (usually 7650). I2PControl is disabled if not specified.
* --i2pcontroladdress=  - Address of I2P control service. Default: 127.0.0.1 (only used if I2PControl is enabled).
* --i2pcontrolpassword= - I2P control service password. Default: "itoopie" (without quotations).

Config
* --tunnelscfg=         - Tunnels Config file. Default: ~/.i2pd/tunnels.cfg -or- /var/lib/i2pd/tunnels.cfg
* --conf=               - Config file. Default: ~/.i2pd/i2p.conf -or- /var/lib/i2pd/i2p.conf
                          This parameter will be silently ignored if the specified config file does not exist.
                          Options specified on the command line take precedence over those in the config file.
* --install=            - Installs the WebUI (see doc/BUILDING.md for details).
