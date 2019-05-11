#LIB_SRC = \
#  BloomFilter.cpp Gzip.cpp Crypto.cpp Datagram.cpp Garlic.cpp DNNPProtocol.cpp LeaseSet.cpp \
#  Log.cpp NTCPSession.cpp NetDb.cpp NetDbRequests.cpp Profiling.cpp \
#  Reseed.cpp RouterContext.cpp RouterInfo.cpp Signature.cpp SSU.cpp \
#  SSUSession.cpp SSUData.cpp Streaming.cpp Identity.cpp TransitTunnel.cpp \
#  Transports.cpp Tunnel.cpp TunnelEndpoint.cpp TunnelPool.cpp TunnelGateway.cpp \
#  Destination.cpp Base.cpp DotNetEndian.cpp FS.cpp Config.cpp Family.cpp \
#  Config.cpp HTTP.cpp Timestamp.cpp util.cpp api.cpp Event.cpp Gost.cpp

LIB_SRC = $(wildcard $(LIB_SRC_DIR)/*.cpp)

#LIB_CLIENT_SRC = \
#	AddressBook.cpp BOB.cpp ClientContext.cpp DotNetTunnel.cpp DotNetService.cpp MatchedDestination.cpp \
#	SAM.cpp SOCKS.cpp HTTPProxy.cpp DNCP.cpp WebSocks.cpp

LIB_CLIENT_SRC = $(wildcard $(LIB_CLIENT_SRC_DIR)/*.cpp)

# also: Daemon{Linux,Win32}.cpp will be added later
#DAEMON_SRC = \
#	HTTPServer.cpp DotNetControl.cpp UPnP.cpp Daemon.cpp dotnet.cpp

DAEMON_SRC = $(wildcard $(DAEMON_SRC_DIR)/*.cpp)
