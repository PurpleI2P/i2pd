Config files
=============

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
    ; * address -- address to listen on, 127.0.0.1 by default
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
