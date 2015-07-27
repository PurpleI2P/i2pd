COMMON_SRC = \
  transport/NTCPSession.cpp transport/SSU.cpp transport/SSUSession.cpp \
  transport/SSUData.cpp transport/Transports.cpp \
  CryptoConst.cpp Datagram.cpp Garlic.cpp I2NPProtocol.cpp LeaseSet.cpp \
  Log.cpp NetDb.cpp NetDbRequests.cpp Profiling.cpp Reseed.cpp \
  RouterContext.cpp RouterInfo.cpp Signature.cpp Streaming.cpp Identity.cpp \
  TransitTunnel.cpp Tunnel.cpp TunnelEndpoint.cpp TunnelPool.cpp \
  TunnelGateway.cpp Destination.cpp UPnP.cpp util.cpp aes.cpp base64.cpp


ifeq ($(UNAME),Darwin)
# This is needed on OS X for some reason I don't understand (yet).
# Else will get linker error about unknown symbols. - torkel
	COMMON_SRC += \
	  AddressBook.cpp BOB.cpp ClientContext.cpp Daemon.cpp I2PTunnel.cpp I2PService.cpp SAM.cpp SOCKS.cpp \
	  UPnP.cpp HTTPServer.cpp HTTPProxy.cpp i2p.cpp DaemonLinux.cpp I2PControl.cpp
endif


# also: Daemon{Linux,Win32}.cpp will be added later
DAEMON_SRC = $(COMMON_SRC) \
	AddressBook.cpp BOB.cpp ClientContext.cpp Daemon.cpp I2PTunnel.cpp I2PService.cpp \
	SAM.cpp SOCKS.cpp HTTPServer.cpp HTTPProxy.cpp I2PControl.cpp i2p.cpp

LIB_SRC := $(COMMON_SRC) \
  api.cpp

TESTS_SRC := $(COMMON_SRC)  \
	tests/Utility.cpp tests/Identity.cpp tests/Data.cpp
