Howto build & run
==================

**Build**

Assuming you're in the root directory of the anoncoin source code.

$ `cd build/docker`
$ `docker -t meeh/dotnet:latest .`

**Run**

To run either the local build, or if not found - fetched prebuild from hub.docker.io, run the following command.

$ `docker run --name anonnode -v /path/to/dotnet/datadir/on/host:/var/lib/dotnet -p 7070:7070 -p 4444:4444 -p 4447:4447 -p 7656:7656 -p 2827:2827 -p 7654:7654 -p 7650:7650  -d meeh/dotnet`

All the ports ( -p HOSTPORT:DOCKERPORT ) is optional. However the command above enable all features (Webconsole, HTTP Proxy, BOB, SAM, dncp, etc)

The volume ( -v HOSTDIR:DOCKERDIR ) is also optional, but if you don't use it, your config, routerid and private keys will die along with the container.

**Options**

Options are set via docker environment variables. This can be set at run with -e parameters.

* **ENABLE_IPV6**   - Enable IPv6 support. Any value can be used - it triggers as long as it's not empty.
* **LOGLEVEL**      - Set the loglevel.
* **ENABLE_AUTH**   - Enable auth for the webconsole. Username and password needs to be set manually in dotnet.conf cause security reasons.

**Logging**

Logging happens to STDOUT as the best practise with docker containers, since infrastructure systems like kubernetes with ELK integration can automatically forward the log to say, kibana or greylog without manual setup. :)



