
CC = g++
CFLAGS = -g -Wall -std=c++0x
OBJECTS = i2p.o base64.o NTCPSession.o RouterInfo.o Transports.o RouterContext.o \
	NetDb.o LeaseSet.o Tunnel.o TunnelEndpoint.o TunnelGateway.o TransitTunnel.o \
	I2NPProtocol.o Log.o Garlic.o HTTPServer.o Streaming.o Identity.o SSU.o util.o
INCFLAGS = 
LDFLAGS = -Wl,-rpath,/usr/local/lib -lcryptopp -lboost_system -lboost_filesystem -lpthread
LIBS = 

all: i2p

i2p: $(OBJECTS)
	$(CC) -o i2p $(OBJECTS) $(LDFLAGS) $(LIBS)

.SUFFIXES:
.SUFFIXES:	.c .cc .C .cpp .o

.cpp.o :
	$(CC) -o $@ -c $(CFLAGS) $< $(INCFLAGS)

clean:
	rm -f *.o

.PHONY: all
.PHONY: clean
