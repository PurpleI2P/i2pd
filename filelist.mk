

CPP_FILES := CryptoConst.cpp base64.cpp NTCPSession.cpp RouterInfo.cpp Transports.cpp \
	RouterContext.cpp NetDb.cpp LeaseSet.cpp Tunnel.cpp TunnelEndpoint.cpp TunnelGateway.cpp \
	TransitTunnel.cpp I2NPProtocol.cpp Log.cpp Garlic.cpp HTTPServer.cpp Streaming.cpp Identity.cpp \
	SSU.cpp util.cpp Reseed.cpp DaemonLinux.cpp SSUData.cpp i2p.cpp aes.cpp SOCKS.cpp UPnP.cpp \
	TunnelPool.cpp HTTPProxy.cpp AddressBook.cpp Daemon.cpp I2PTunnel.cpp


H_FILES := CryptoConst.h base64.h NTCPSession.h RouterInfo.h Transports.h \
	RouterContext.h NetDb.h LeaseSet.h Tunnel.h TunnelEndpoint.h TunnelGateway.h \
	TransitTunnel.h I2NPProtocol.h Log.h Garlic.h HTTPServer.h Streaming.h Identity.h \
	SSU.h util.h Reseed.h DaemonLinux.h SSUData.h i2p.h aes.h SOCKS.h UPnP.h TunnelPool.h \
	HTTPProxy.h AddressBook.h Daemon.h I2PTunnel.h version.h Signature.h


OBJECTS = $(addprefix obj/, $(notdir $(CPP_FILES:.cpp=.o)))

