QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = i2pd_qt
TEMPLATE = app
QMAKE_CXXFLAGS *= -std=c++11 -Wno-unused-parameter -Wno-maybe-uninitialized

DEFINES += USE_UPNP

CONFIG(debug, debug|release) {
    message(Debug build)
    DEFINES += DEBUG_WITH_DEFAULT_LOGGING
} else {
    message(Release build)
}

SOURCES += DaemonQT.cpp mainwindow.cpp \
    ../../libi2pd/api.cpp \
    ../../libi2pd/Base.cpp \
    ../../libi2pd/Blinding.cpp \
    ../../libi2pd/BloomFilter.cpp \
    ../../libi2pd/ChaCha20.cpp \
    ../../libi2pd/Config.cpp \
    ../../libi2pd/CPU.cpp \
    ../../libi2pd/Crypto.cpp \
    ../../libi2pd/CryptoKey.cpp \
    ../../libi2pd/Datagram.cpp \
    ../../libi2pd/Destination.cpp \
    ../../libi2pd/Ed25519.cpp \
    ../../libi2pd/Family.cpp \
    ../../libi2pd/FS.cpp \
    ../../libi2pd/Garlic.cpp \
    ../../libi2pd/Gost.cpp \
    ../../libi2pd/Gzip.cpp \
    ../../libi2pd/HTTP.cpp \
    ../../libi2pd/I2NPProtocol.cpp \
    ../../libi2pd/I2PEndian.cpp \
    ../../libi2pd/Identity.cpp \
    ../../libi2pd/LeaseSet.cpp \
    ../../libi2pd/Log.cpp \
    ../../libi2pd/NetDb.cpp \
    ../../libi2pd/NetDbRequests.cpp \
    ../../libi2pd/NTCP2.cpp \
    ../../libi2pd/NTCPSession.cpp \
    ../../libi2pd/Poly1305.cpp \
    ../../libi2pd/Profiling.cpp \
    ../../libi2pd/Reseed.cpp \
    ../../libi2pd/RouterContext.cpp \
    ../../libi2pd/RouterInfo.cpp \
    ../../libi2pd/Signature.cpp \
    ../../libi2pd/SSU.cpp \
    ../../libi2pd/SSUData.cpp \
    ../../libi2pd/SSUSession.cpp \
    ../../libi2pd/Streaming.cpp \
    ../../libi2pd/Timestamp.cpp \
    ../../libi2pd/TransitTunnel.cpp \
    ../../libi2pd/Transports.cpp \
    ../../libi2pd/Tunnel.cpp \
    ../../libi2pd/TunnelEndpoint.cpp \
    ../../libi2pd/TunnelGateway.cpp \
    ../../libi2pd/TunnelPool.cpp \
    ../../libi2pd/util.cpp \
    ../../libi2pd/Elligator.cpp \
    ../../libi2pd/ECIESX25519AEADRatchetSession.cpp \
    ../../libi2pd_client/AddressBook.cpp \
    ../../libi2pd_client/BOB.cpp \
    ../../libi2pd_client/ClientContext.cpp \
    ../../libi2pd_client/HTTPProxy.cpp \
    ../../libi2pd_client/I2CP.cpp \
    ../../libi2pd_client/I2PService.cpp \
    ../../libi2pd_client/I2PTunnel.cpp \
    ../../libi2pd_client/MatchedDestination.cpp \
    ../../libi2pd_client/SAM.cpp \
    ../../libi2pd_client/SOCKS.cpp \
    ../../daemon/Daemon.cpp \
    ../../daemon/HTTPServer.cpp \
    ../../daemon/I2PControl.cpp \
    ../../daemon/i2pd.cpp \
    ../../daemon/UPnP.cpp \
    ClientTunnelPane.cpp \
    MainWindowItems.cpp \
    ServerTunnelPane.cpp \
    SignatureTypeComboboxFactory.cpp \
    TunnelConfig.cpp \
    TunnelPane.cpp \
    textbrowsertweaked1.cpp \
    pagewithbackbutton.cpp \
    widgetlock.cpp \
    widgetlockregistry.cpp \
    logviewermanager.cpp \
    DelayedSaveManager.cpp \
    Saver.cpp \
    DelayedSaveManagerImpl.cpp \
    SaverImpl.cpp

HEADERS  += DaemonQT.h mainwindow.h \
    ../../libi2pd/api.h \
    ../../libi2pd/Base.h \
    ../../libi2pd/Blinding.h \
    ../../libi2pd/BloomFilter.h \
    ../../libi2pd/ChaCha20.h \
    ../../libi2pd/Config.h \
    ../../libi2pd/CPU.h \
    ../../libi2pd/Crypto.h \
    ../../libi2pd/CryptoKey.h \
    ../../libi2pd/CryptoWorker.h \
    ../../libi2pd/Datagram.h \
    ../../libi2pd/Destination.h \
    ../../libi2pd/Ed25519.h \
    ../../libi2pd/Family.h \
    ../../libi2pd/FS.h \
    ../../libi2pd/Garlic.h \
    ../../libi2pd/Gost.h \
    ../../libi2pd/Gzip.h \
    ../../libi2pd/HTTP.h \
    ../../libi2pd/I2NPProtocol.h \
    ../../libi2pd/I2PEndian.h \
    ../../libi2pd/Identity.h \
    ../../libi2pd/LeaseSet.h \
    ../../libi2pd/LittleBigEndian.h \
    ../../libi2pd/Log.h \
    ../../libi2pd/NetDb.hpp \
    ../../libi2pd/NetDbRequests.h \
    ../../libi2pd/NTCP2.h \
    ../../libi2pd/NTCPSession.h \
    ../../libi2pd/Poly1305.h \
    ../../libi2pd/Profiling.h \
    ../../libi2pd/Queue.h \
    ../../libi2pd/Reseed.h \
    ../../libi2pd/RouterContext.h \
    ../../libi2pd/RouterInfo.h \
    ../../libi2pd/Signature.h \
    ../../libi2pd/Siphash.h \
    ../../libi2pd/SSU.h \
    ../../libi2pd/SSUData.h \
    ../../libi2pd/SSUSession.h \
    ../../libi2pd/Streaming.h \
    ../../libi2pd/Tag.h \
    ../../libi2pd/Timestamp.h \
    ../../libi2pd/TransitTunnel.h \
    ../../libi2pd/Transports.h \
    ../../libi2pd/TransportSession.h \
    ../../libi2pd/Tunnel.h \
    ../../libi2pd/TunnelBase.h \
    ../../libi2pd/TunnelConfig.h \
    ../../libi2pd/TunnelEndpoint.h \
    ../../libi2pd/TunnelGateway.h \
    ../../libi2pd/TunnelPool.h \
    ../../libi2pd/util.h \
    ../../libi2pd/version.h \
    ../../libi2pd/Elligator.h \
    ../../libi2pd/ECIESX25519AEADRatchetSession.h \
    ../../libi2pd_client/AddressBook.h \
    ../../libi2pd_client/BOB.h \
    ../../libi2pd_client/ClientContext.h \
    ../../libi2pd_client/HTTPProxy.h \
    ../../libi2pd_client/I2CP.h \
    ../../libi2pd_client/I2PService.h \
    ../../libi2pd_client/I2PTunnel.h \
    ../../libi2pd_client/MatchedDestination.h \
    ../../libi2pd_client/SAM.h \
    ../../libi2pd_client/SOCKS.h \
    ../../daemon/Daemon.h \
    ../../daemon/HTTPServer.h \
    ../../daemon/I2PControl.h \
    ../../daemon/UPnP.h \
    ClientTunnelPane.h \
    MainWindowItems.h \
    ServerTunnelPane.h \
    SignatureTypeComboboxFactory.h \
    TunnelConfig.h \
    TunnelPane.h \
    TunnelsPageUpdateListener.h \
    textbrowsertweaked1.h \
    pagewithbackbutton.h \
    widgetlock.h \
    widgetlockregistry.h \
    i2pd.rc \
    logviewermanager.h \
    DelayedSaveManager.h \
    Saver.h \
    DelayedSaveManagerImpl.h \
    SaverImpl.h

INCLUDEPATH += ../../libi2pd
INCLUDEPATH += ../../libi2pd_client
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
	LIBS += -Wl,-dead_strip
	LIBS += -Wl,-dead_strip_dylibs
	LIBS += -Wl,-bind_at_load
}

linux:!android {
        message("Using Linux settings")
        LIBS += -lcrypto -lssl -lboost_system -lboost_date_time -lboost_filesystem -lboost_program_options -lpthread -lminiupnpc
}

windows {
        message("Using Windows settings")
        RC_FILE = i2pd.rc
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
	#sources.files = $$SOURCES $$HEADERS $$RESOURCES $$FORMS i2pd_qt.pro resources images
	RESOURCES = i2pd.qrc
	QT += xml
	#INSTALLS += sources
}

