QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = i2pd_qt
TEMPLATE = app
QMAKE_CXXFLAGS *= -std=c++11
DEFINES += USE_UPNP

# change to your own path, where you will store all needed libraries with 'git clone' commands below.
MAIN_PATH = /path/to/libraries

# git clone https://github.com/PurpleI2P/Boost-for-Android-Prebuilt.git
# git clone https://github.com/PurpleI2P/OpenSSL-for-Android-Prebuilt.git
# git clone https://github.com/PurpleI2P/MiniUPnP-for-Android-Prebuilt.git
# git clone https://github.com/PurpleI2P/android-ifaddrs.git
BOOST_PATH = $$MAIN_PATH/Boost-for-Android-Prebuilt
OPENSSL_PATH = $$MAIN_PATH/OpenSSL-for-Android-Prebuilt
MINIUPNP_PATH = $$MAIN_PATH/MiniUPnP-for-Android-Prebuilt
IFADDRS_PATH = $$MAIN_PATH/android-ifaddrs

# Steps in Android SDK manager:
# 1) Check Extras/Google Support Library https://developer.android.com/topic/libraries/support-library/setup.html
# 2) Check API 11
# Finally, click Install.

SOURCES += DaemonQT.cpp mainwindow.cpp \
    ../../libi2pd/api.cpp \
    ../../libi2pd/Base.cpp \
    ../../libi2pd/BloomFilter.cpp \
    ../../libi2pd/Config.cpp \
    ../../libi2pd/Crypto.cpp \
    ../../libi2pd/Datagram.cpp \
    ../../libi2pd/Destination.cpp \
    ../../libi2pd/Event.cpp \
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
    ../../libi2pd/NTCPSession.cpp \
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
    ../../libi2pd_client/Websocket.cpp \
    ../../libi2pd_client/WebSocks.cpp \
    ClientTunnelPane.cpp \
    MainWindowItems.cpp \
    ServerTunnelPane.cpp \
    SignatureTypeComboboxFactory.cpp \
    TunnelConfig.cpp \
    TunnelPane.cpp \
    ../../daemon/Daemon.cpp \
    ../../daemon/HTTPServer.cpp \
    ../../daemon/i2pd.cpp \
    ../../daemon/I2PControl.cpp \
    ../../daemon/UnixDaemon.cpp \
    ../../daemon/UPnP.cpp \
    textbrowsertweaked1.cpp \
    pagewithbackbutton.cpp \
    widgetlock.cpp \
    widgetlockregistry.cpp

#qt creator does not handle this well
#SOURCES += $$files(../../libi2pd/*.cpp)
#SOURCES += $$files(../../libi2pd_client/*.cpp)
#SOURCES += $$files(../../daemon/*.cpp)
#SOURCES += $$files(./*.cpp)

SOURCES -= ../../daemon/UnixDaemon.cpp

HEADERS  += DaemonQT.h mainwindow.h \
    ../../libi2pd/api.h \
    ../../libi2pd/Base.h \
    ../../libi2pd/BloomFilter.h \
    ../../libi2pd/Config.h \
    ../../libi2pd/Crypto.h \
    ../../libi2pd/Datagram.h \
    ../../libi2pd/Destination.h \
    ../../libi2pd/Event.h \
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
    ../../libi2pd/NTCPSession.h \
    ../../libi2pd/Profiling.h \
    ../../libi2pd/Queue.h \
    ../../libi2pd/Reseed.h \
    ../../libi2pd/RouterContext.h \
    ../../libi2pd/RouterInfo.h \
    ../../libi2pd/Signature.h \
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
    ../../libi2pd_client/Websocket.h \
    ../../libi2pd_client/WebSocks.h \
    ClientTunnelPane.h \
    MainWindowItems.h \
    ServerTunnelPane.h \
    SignatureTypeComboboxFactory.h \
    TunnelConfig.h \
    TunnelPane.h \
    TunnelsPageUpdateListener.h \
    ../../daemon/Daemon.h \
    ../../daemon/HTTPServer.h \
    ../../daemon/I2PControl.h \
    ../../daemon/UPnP.h \
    textbrowsertweaked1.h \
    pagewithbackbutton.h \
    widgetlock.h \
    widgetlockregistry.h

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
}

android {
	message("Using Android settings")
        DEFINES += ANDROID=1
	DEFINES += __ANDROID__

        CONFIG += mobility

        MOBILITY =

        INCLUDEPATH += $$BOOST_PATH/boost_1_53_0/include \
		$$OPENSSL_PATH/openssl-1.0.2/include \
		$$MINIUPNP_PATH/miniupnp-2.0/include \
		$$IFADDRS_PATH
	DISTFILES += android/AndroidManifest.xml

	ANDROID_PACKAGE_SOURCE_DIR = $$PWD/android

	SOURCES += $$IFADDRS_PATH/ifaddrs.c
	HEADERS += $$IFADDRS_PATH/ifaddrs.h

	equals(ANDROID_TARGET_ARCH, armeabi-v7a){
		DEFINES += ANDROID_ARM7A
		# http://stackoverflow.com/a/30235934/529442
		LIBS += -L$$BOOST_PATH/boost_1_53_0/armeabi-v7a/lib \
			-lboost_system-gcc-mt-1_53 -lboost_date_time-gcc-mt-1_53 \
			-lboost_filesystem-gcc-mt-1_53 -lboost_program_options-gcc-mt-1_53 \
			-L$$OPENSSL_PATH/openssl-1.0.2/armeabi-v7a/lib/ -lcrypto -lssl \
			-L$$MINIUPNP_PATH/miniupnp-2.0/armeabi-v7a/lib/ -lminiupnpc

		PRE_TARGETDEPS += $$OPENSSL_PATH/openssl-1.0.2/armeabi-v7a/lib/libcrypto.a \
			$$OPENSSL_PATH/openssl-1.0.2/armeabi-v7a/lib/libssl.a
		DEPENDPATH += $$OPENSSL_PATH/openssl-1.0.2/include

		ANDROID_EXTRA_LIBS += $$OPENSSL_PATH/openssl-1.0.2/armeabi-v7a/lib/libcrypto_1_0_0.so \
			$$OPENSSL_PATH/openssl-1.0.2/armeabi-v7a/lib/libssl_1_0_0.so \
			$$MINIUPNP_PATH/miniupnp-2.0/armeabi-v7a/lib/libminiupnpc.so
	}

	equals(ANDROID_TARGET_ARCH, x86){
		# http://stackoverflow.com/a/30235934/529442
		LIBS += -L$$BOOST_PATH/boost_1_53_0/x86/lib \
			-lboost_system-gcc-mt-1_53 -lboost_date_time-gcc-mt-1_53 \
			-lboost_filesystem-gcc-mt-1_53 -lboost_program_options-gcc-mt-1_53 \
			-L$$OPENSSL_PATH/openssl-1.0.2/x86/lib/ -lcrypto -lssl \
			-L$$MINIUPNP_PATH/miniupnp-2.0/x86/lib/ -lminiupnpc

		PRE_TARGETDEPS += $$OPENSSL_PATH/openssl-1.0.2/x86/lib/libcrypto.a \
			$$OPENSSL_PATH/openssl-1.0.2/x86/lib/libssl.a

		DEPENDPATH += $$OPENSSL_PATH/openssl-1.0.2/include

		ANDROID_EXTRA_LIBS += $$OPENSSL_PATH/openssl-1.0.2/x86/lib/libcrypto_1_0_0.so \
			$$OPENSSL_PATH/openssl-1.0.2/x86/lib/libssl_1_0_0.so \
			$$MINIUPNP_PATH/miniupnp-2.0/x86/lib/libminiupnpc.so
	}
}

linux:!android {
	message("Using Linux settings")
	LIBS += -lcrypto -lssl -lboost_system -lboost_date_time -lboost_filesystem -lboost_program_options -lpthread -lminiupnpc
}

!android:!symbian:!maemo5:!simulator {
	message("Build with a system tray icon")
	# see also http://doc.qt.io/qt-4.8/qt-desktop-systray-systray-pro.html for example on wince*
	#sources.files = $$SOURCES $$HEADERS $$RESOURCES $$FORMS i2pd_qt.pro resources images
	RESOURCES = i2pd.qrc
	QT += xml
	#INSTALLS += sources
}

