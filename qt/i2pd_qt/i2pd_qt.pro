QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = dotnet_qt
TEMPLATE = app
QMAKE_CXXFLAGS *= -std=c++11 -ggdb
DEFINES += USE_UPNP

SOURCES += DaemonQT.cpp mainwindow.cpp \
    ../../libdotnet/api.cpp \
    ../../libdotnet/Base.cpp \
    ../../libdotnet/BloomFilter.cpp \
    ../../libdotnet/Config.cpp \
    ../../libdotnet/CPU.cpp \
    ../../libdotnet/Crypto.cpp \
	../../libdotnet/CryptoKey.cpp \
    ../../libdotnet/Datagram.cpp \
    ../../libdotnet/Destination.cpp \
    ../../libdotnet/Event.cpp \
    ../../libdotnet/Family.cpp \
    ../../libdotnet/FS.cpp \
    ../../libdotnet/Garlic.cpp \
    ../../libdotnet/Gost.cpp \
    ../../libdotnet/Gzip.cpp \
    ../../libdotnet/HTTP.cpp \
    ../../libdotnet/DNNPProtocol.cpp \
    ../../libdotnet/DotNetEndian.cpp \
    ../../libdotnet/Identity.cpp \
    ../../libdotnet/LeaseSet.cpp \
    ../../libdotnet/Log.cpp \
    ../../libdotnet/NetDb.cpp \
    ../../libdotnet/NetDbRequests.cpp \
    ../../libdotnet/NTCPSession.cpp \
    ../../libdotnet/Profiling.cpp \
    ../../libdotnet/Reseed.cpp \
    ../../libdotnet/RouterContext.cpp \
    ../../libdotnet/RouterInfo.cpp \
    ../../libdotnet/Signature.cpp \
    ../../libdotnet/SSU.cpp \
    ../../libdotnet/SSUData.cpp \
    ../../libdotnet/SSUSession.cpp \
    ../../libdotnet/Streaming.cpp \
    ../../libdotnet/Timestamp.cpp \
    ../../libdotnet/TransitTunnel.cpp \
    ../../libdotnet/Transports.cpp \
    ../../libdotnet/Tunnel.cpp \
    ../../libdotnet/TunnelEndpoint.cpp \
    ../../libdotnet/TunnelGateway.cpp \
    ../../libdotnet/TunnelPool.cpp \
    ../../libdotnet/util.cpp \
    ../../libdotnet/Ed25519.cpp \
    ../../libdotnet/Chacha20.cpp \
    ../../libdotnet/Poly1305.cpp \    
    ../../libdotnet_client/AddressBook.cpp \
    ../../libdotnet_client/BOB.cpp \
    ../../libdotnet_client/ClientContext.cpp \
    ../../libdotnet_client/HTTPProxy.cpp \
    ../../libdotnet_client/DNCP.cpp \
    ../../libdotnet_client/DotNetService.cpp \
    ../../libdotnet_client/DotNetTunnel.cpp \
    ../../libdotnet_client/MatchedDestination.cpp \
    ../../libdotnet_client/SAM.cpp \
    ../../libdotnet_client/SOCKS.cpp \
    ../../libdotnet_client/Websocket.cpp \
    ../../libdotnet_client/WebSocks.cpp \
    ClientTunnelPane.cpp \
    MainWindowItems.cpp \
    ServerTunnelPane.cpp \
    SignatureTypeComboboxFactory.cpp \
    TunnelConfig.cpp \
    TunnelPane.cpp \
    ../../daemon/Daemon.cpp \
    ../../daemon/HTTPServer.cpp \
    ../../daemon/dotnet.cpp \
    ../../daemon/DotNetControl.cpp \
    ../../daemon/UnixDaemon.cpp \
    ../../daemon/UPnP.cpp \
    textbrowsertweaked1.cpp \
    pagewithbackbutton.cpp \
    widgetlock.cpp \
    widgetlockregistry.cpp \
    logviewermanager.cpp \
    ../../libdotnet/NTCP2.cpp

#qt creator does not handle this well
#SOURCES += $$files(../../libdotnet/*.cpp)
#SOURCES += $$files(../../libdotnet_client/*.cpp)
#SOURCES += $$files(../../daemon/*.cpp)
#SOURCES += $$files(./*.cpp)

SOURCES -= ../../daemon/UnixDaemon.cpp

HEADERS  += DaemonQT.h mainwindow.h \
    ../../libdotnet/api.h \
    ../../libdotnet/Base.h \
    ../../libdotnet/BloomFilter.h \
    ../../libdotnet/Config.h \
    ../../libdotnet/Crypto.h \
	../../libdotnet/CryptoKey.h \
    ../../libdotnet/Datagram.h \
    ../../libdotnet/Destination.h \
    ../../libdotnet/Event.h \
    ../../libdotnet/Family.h \
    ../../libdotnet/FS.h \
    ../../libdotnet/Garlic.h \
    ../../libdotnet/Gost.h \
    ../../libdotnet/Gzip.h \
    ../../libdotnet/HTTP.h \
    ../../libdotnet/DNNPProtocol.h \
    ../../libdotnet/DotNetEndian.h \
    ../../libdotnet/Identity.h \
    ../../libdotnet/LeaseSet.h \
    ../../libdotnet/LittleBigEndian.h \
    ../../libdotnet/Log.h \
    ../../libdotnet/NetDb.hpp \
    ../../libdotnet/NetDbRequests.h \
    ../../libdotnet/NTCPSession.h \
    ../../libdotnet/Profiling.h \
    ../../libdotnet/Queue.h \
    ../../libdotnet/Reseed.h \
    ../../libdotnet/RouterContext.h \
    ../../libdotnet/RouterInfo.h \
    ../../libdotnet/Signature.h \
    ../../libdotnet/SSU.h \
    ../../libdotnet/SSUData.h \
    ../../libdotnet/SSUSession.h \
    ../../libdotnet/Streaming.h \
    ../../libdotnet/Tag.h \
    ../../libdotnet/Timestamp.h \
    ../../libdotnet/TransitTunnel.h \
    ../../libdotnet/Transports.h \
    ../../libdotnet/TransportSession.h \
    ../../libdotnet/Tunnel.h \
    ../../libdotnet/TunnelBase.h \
    ../../libdotnet/TunnelConfig.h \
    ../../libdotnet/TunnelEndpoint.h \
    ../../libdotnet/TunnelGateway.h \
    ../../libdotnet/TunnelPool.h \
    ../../libdotnet/util.h \
    ../../libdotnet/version.h \
    ../../libdotnet_client/AddressBook.h \
    ../../libdotnet_client/BOB.h \
    ../../libdotnet_client/ClientContext.h \
    ../../libdotnet_client/HTTPProxy.h \
    ../../libdotnet_client/DNCP.h \
    ../../libdotnet_client/DotNetService.h \
    ../../libdotnet_client/DotNetTunnel.h \
    ../../libdotnet_client/MatchedDestination.h \
    ../../libdotnet_client/SAM.h \
    ../../libdotnet_client/SOCKS.h \
    ../../libdotnet_client/Websocket.h \
    ../../libdotnet_client/WebSocks.h \
    ClientTunnelPane.h \
    MainWindowItems.h \
    ServerTunnelPane.h \
    SignatureTypeComboboxFactory.h \
    TunnelConfig.h \
    TunnelPane.h \
    TunnelsPageUpdateListener.h \
    ../../daemon/Daemon.h \
    ../../daemon/HTTPServer.h \
    ../../daemon/DotNetControl.h \
    ../../daemon/UPnP.h \
    textbrowsertweaked1.h \
    pagewithbackbutton.h \
    widgetlock.h \
    widgetlockregistry.h \
    dotnet.rc \
    dotnet.rc \
    logviewermanager.h

INCLUDEPATH += ../../libdotnet
INCLUDEPATH += ../../libdotnet_client
INCLUDEPATH += ../../daemon
INCLUDEPATH += .

FORMS += mainwindow.ui \
    tunnelform.ui \
    statusbuttons.ui \
    routercommandswidget.ui \
    generalsettingswidget.ui

LIBS += -lz

macx {
	message("using mac os x target")
	BREWROOT=/usr/local
	BOOSTROOT=$$BREWROOT/opt/boost
	SSLROOT=$$BREWROOT/opt/libressl
	UPNPROOT=$$BREWROOT/opt/miniupnpc
	INCLUDEPATH += $$BOOSTROOT/include
	INCLUDEPATH += $$SSLROOT/include
	INCLUDEPATH += $$UPNPROOT/include
	LIBS += $$SSLROOT/lib/libcrypto.a
	LIBS += $$SSLROOT/lib/libssl.a
	LIBS += $$BOOSTROOT/lib/libboost_system.a
	LIBS += $$BOOSTROOT/lib/libboost_date_time.a
	LIBS += $$BOOSTROOT/lib/libboost_filesystem.a
	LIBS += $$BOOSTROOT/lib/libboost_program_options.a
	LIBS += $$UPNPROOT/lib/libminiupnpc.a
}

linux:!android {
        message("Using Linux settings")
        LIBS += -lcrypto -lssl -lboost_system -lboost_date_time -lboost_filesystem -lboost_program_options -lpthread -lminiupnpc
}

windows {
        message("Using Windows settings")
        RC_FILE = dotnet.rc
        DEFINES += BOOST_USE_WINDOWS_H WINDOWS _WINDOWS WIN32_LEAN_AND_MEAN MINIUPNP_STATICLIB
        DEFINES -= UNICODE _UNICODE
        BOOST_SUFFIX = -mt
        QMAKE_CXXFLAGS_RELEASE = -Os
        QMAKE_LFLAGS = -Wl,-Bstatic -static-libgcc -static-libstdc++ -mwindows

        #linker's -s means "strip"
        QMAKE_LFLAGS_RELEASE += -s

        LIBS = -lminiupnpc \
        -lboost_system$$BOOST_SUFFIX \
        -lboost_date_time$$BOOST_SUFFIX \
        -lboost_filesystem$$BOOST_SUFFIX \
        -lboost_program_options$$BOOST_SUFFIX \
        -lssl \
        -lcrypto \
        -lz \
        -lwsock32 \
        -lws2_32 \
        -lgdi32 \
        -liphlpapi \
        -lstdc++ \
        -lpthread
}

!android:!symbian:!maemo5:!simulator {
	message("Build with a system tray icon")
	# see also http://doc.qt.io/qt-4.8/qt-desktop-systray-systray-pro.html for example on wince*
	#sources.files = $$SOURCES $$HEADERS $$RESOURCES $$FORMS dotnet_qt.pro resources images
	RESOURCES = dotnet.qrc
	QT += xml
	#INSTALLS += sources
}

