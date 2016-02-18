LIB_SRC = \
  Crypto.cpp Datagram.cpp Garlic.cpp I2NPProtocol.cpp LeaseSet.cpp \
  Log.cpp NTCPSession.cpp NetDb.cpp NetDbRequests.cpp Profiling.cpp \
  Reseed.cpp RouterContext.cpp RouterInfo.cpp Signature.cpp SSU.cpp \
  SSUSession.cpp SSUData.cpp Streaming.cpp Identity.cpp TransitTunnel.cpp \
  Transports.cpp Tunnel.cpp TunnelEndpoint.cpp TunnelPool.cpp TunnelGateway.cpp \
  Destination.cpp Base.cpp I2PEndian.cpp Config.cpp Family.cpp util.cpp \
  api.cpp

LIB_CLIENT_SRC = \
	AddressBook.cpp BOB.cpp ClientContext.cpp I2PTunnel.cpp I2PService.cpp \
	SAM.cpp SOCKS.cpp HTTPProxy.cpp

# also: Daemon{Linux,Win32}.cpp will be added later
DAEMON_SRC = \
	HTTPServer.cpp I2PControl.cpp UPnP.cpp Daemon.cpp Config.cpp i2pd.cpp

