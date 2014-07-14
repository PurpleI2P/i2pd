TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

TARGET = ./../../i2pd_qt

QMAKE_CXXFLAGS += -std=c++0x

LIBS += -lcrypto++
LIBS += \
       -lboost_system\
       -lboost_filesystem\
       -lboost_regex\
       -lboost_program_options\
       -lpthread

SOURCES += \
    ../LeaseSet.cpp \
    ../i2p.cpp \
    ../HTTPServer.cpp \
    ../HTTPProxy.cpp \
    ../Garlic.cpp \
    ../base64.cpp \
    ../AddressBook.cpp \
    ../util.cpp \
    ../UPnP.cpp \
    ../TunnelPool.cpp \
    ../TunnelGateway.cpp \
    ../TunnelEndpoint.cpp \
    ../Tunnel.cpp \
    ../Transports.cpp \
    ../TransitTunnel.cpp \
    ../Streaming.cpp \
    ../SSU.cpp \
    ../RouterInfo.cpp \
    ../RouterContext.cpp \
    ../Reseed.cpp \
    ../NTCPSession.cpp \
    ../NetDb.cpp \
    ../Log.cpp \
    ../Identity.cpp \
    ../I2NPProtocol.cpp \
    ../SOCKS.cpp

HEADERS += \
    ../LeaseSet.h \
    ../Identity.h \
    ../HTTPServer.h \
    ../HTTPProxy.h \
    ../hmac.h \
    ../Garlic.h \
    ../ElGamal.h \
    ../CryptoConst.h \
    ../base64.h \
    ../AddressBook.h \
    ../util.h \
    ../UPnP.h \
    ../TunnelPool.h \
    ../TunnelGateway.h \
    ../TunnelEndpoint.h \
    ../TunnelConfig.h \
    ../TunnelBase.h \
    ../Tunnel.h \
    ../Transports.h \
    ../TransitTunnel.h \
    ../Timestamp.h \
    ../Streaming.h \
    ../SSU.h \
    ../RouterInfo.h \
    ../RouterContext.h \
    ../Reseed.h \
    ../Queue.h \
    ../NTCPSession.h \
    ../NetDb.h \
    ../Log.h \
    ../LittleBigEndian.h \
    ../I2PEndian.h \
    ../I2NPProtocol.h \
    ../SOCKS.h

OTHER_FILES += \
    ../README.md \
    ../Makefile \
    ../LICENSE
