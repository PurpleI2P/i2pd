

CPP_FILES := ../CryptoConst.cpp ../base64.cpp ../NTCPSession.cpp ../RouterInfo.cpp \
	../Transports.cpp ../RouterContext.cpp ../NetDb.cpp ../LeaseSet.cpp Tunnel.cpp \
	../TunnelEndpoint.cpp ../TunnelGateway.cpp ../TransitTunnel.cpp ../I2NPProtocol.cpp \
	../Log.cpp ../Garlic.cpp ../Streaming.cpp ../Destination.cpp ../Identity.cpp \
	../SSU.cpp ../SSUSession.cpp ../SSUData.cpp ../util.cpp ../Reseed.cpp ../SSUData.cpp \
	../aes.cpp ../TunnelPool.cpp ../AddressBook.cpp ../Datagram.cpp api.cpp


H_FILES := ../CryptoConst.h ../base64.h ../NTCPSession.h ../RouterInfo.h ../Transports.h \
	../RouterContext.h ../NetDb.h ../LeaseSet.h ../Tunnel.h ../TunnelEndpoint.h \
	../TunnelGateway.h ../TransitTunnel.h ../I2NPProtocol.h ../Log.h ../Garlic.h \
	../Streaming.h ../Destination.h ../Identity.h ../SSU.h ../SSUSession.h ../SSUData.h \
	../util.h ../Reseed.h ../SSUData.h ../aes.h ../TunnelPool.h ../AddressBook.h ../version.h \
	../Signature.h ../TransportSession.h ../Datagram.h api.h

OBJECTS = $(addprefix obj/, $(notdir $(CPP_FILES:.cpp=.o)))

