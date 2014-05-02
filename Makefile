
CC = g++
CFLAGS = -g -Wall -std=c++0x
OBJECTS = obj/CryptoConst.o obj/base64.o obj/NTCPSession.o obj/RouterInfo.o obj/Transports.o \
	obj/RouterContext.o obj/NetDb.o obj/LeaseSet.o obj/Tunnel.o obj/TunnelEndpoint.o \
    obj/TunnelGateway.o obj/TransitTunnel.o obj/I2NPProtocol.o obj/Log.o obj/Garlic.o \
    obj/HTTPServer.o obj/Streaming.o obj/Identity.o obj/SSU.o obj/util.o obj/Reseed.o \
    obj/UPnP.o obj/TunnelPool.o obj/HTTPProxy.o obj/AddressBook.o  obj/Daemon.o \
    obj/DaemonLinux.o obj/SSUData.o obj/i2p.o
INCFLAGS = 
LDFLAGS = -Wl,-rpath,/usr/local/lib -lcryptopp -lboost_system -lboost_filesystem -lboost_regex -lboost_program_options -lpthread
LIBS = 

all: obj i2p

i2p: $(OBJECTS:obj/%=obj/%)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

.SUFFIXES:
.SUFFIXES:	.c .cc .C .cpp .o

obj/%.o : %.cpp
	$(CC) -o $@ $< -c $(CFLAGS) $(INCFLAGS)

obj:
	mkdir -p obj

clean:
	rm -fr obj i2p

.PHONY: all
.PHONY: clean

