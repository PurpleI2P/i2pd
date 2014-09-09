bin_PROGRAMS	= i2p
i2p_SOURCES	= AddressBook.cpp CryptoConst.cpp Daemon.cpp		\
		  DaemonLinux.cpp DaemonWin32.cpp Garlic.cpp		\
		  HTTPProxy.cpp HTTPServer.cpp I2NPProtocol.cpp		\
		  I2PTunnel.cpp Identity.cpp LeaseSet.cpp Log.cpp	\
		  NTCPSession.cpp NetDb.cpp Reseed.cpp			\
		  RouterContext.cpp RouterInfo.cpp SOCKS.cpp SSU.cpp	\
		  SSUData.cpp Streaming.cpp TransitTunnel.cpp		\
		  Transports.cpp Tunnel.cpp TunnelEndpoint.cpp		\
		  TunnelGateway.cpp TunnelPool.cpp UPnP.cpp aes.cpp	\
		  base64.cpp i2p.cpp util.cpp 		  		\
		  							\
		  AddressBook.h CryptoConst.h Daemon.h ElGamal.h	\
		  Garlic.h HTTPProxy.h HTTPServer.h I2NPProtocol.h	\
		  I2PEndian.h I2PTunnel.h Identity.h LeaseSet.h		\
		  LittleBigEndian.h Log.h NTCPSession.h NetDb.h Queue.h	\
		  Reseed.h RouterContext.h RouterInfo.h SOCKS.h SSU.h	\
		  SSUData.h Signature.h Streaming.h Timestamp.h		\
		  TransitTunnel.h Transports.h Tunnel.h TunnelBase.h	\
		  TunnelConfig.h TunnelEndpoint.h TunnelGateway.h	\
		  TunnelPool.h UPnP.h aes.h base64.h config.h hmac.h	\
		  util.h version.h

AM_LDFLAGS	= @BOOST_DATE_TIME_LIB@ @BOOST_FILESYSTEM_LIB@		\
		  @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_REGEX_LIB@		\
		  @BOOST_SYSTEM_LIB@
