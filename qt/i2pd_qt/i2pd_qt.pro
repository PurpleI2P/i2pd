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
	../../HTTPServer.cpp ../../I2PControl.cpp ../../Daemon.cpp ../../Config.cpp \
	../../AddressBook.cpp ../../api.cpp ../../Base.cpp ../../BOB.cpp ../../ClientContext.cpp \
	../../Crypto.cpp ../../Datagram.cpp ../../Destination.cpp ../../Family.cpp ../../FS.cpp \
	../../Garlic.cpp ../../HTTP.cpp ../../HTTPProxy.cpp ../../I2CP.cpp ../../I2NPProtocol.cpp \
	../../I2PEndian.cpp ../../I2PService.cpp ../../I2PTunnel.cpp ../../Identity.cpp \
	../../LeaseSet.cpp ../../Log.cpp ../../NetDb.cpp ../../NetDbRequests.cpp \
	../../NTCPSession.cpp ../../Profiling.cpp ../../Reseed.cpp ../../RouterContext.cpp \
	../../RouterInfo.cpp ../../SAM.cpp ../../Signature.cpp ../../SOCKS.cpp ../../SSU.cpp \
	../../SSUData.cpp ../../SSUSession.cpp ../../Streaming.cpp ../../TransitTunnel.cpp \
	../../Transports.cpp ../../Tunnel.cpp ../../TunnelEndpoint.cpp ../../TunnelGateway.cpp \
	../../TunnelPool.cpp ../../UPnP.cpp ../../Gzip.cpp ../../Timestamp.cpp ../../util.cpp \
	../../Event.cpp ../../BloomFiler.cpp ../../Gost.cpp ../../MatchedDestination.cpp \
	../../i2pd.cpp

HEADERS  += DaemonQT.h mainwindow.h \
	../../HTTPServer.h ../../I2PControl.h ../../UPnP.h ../../Daemon.h ../../Config.h \
	../../AddressBook.h ../../api.h ../../Base.h ../../BOB.h ../../ClientContext.h \
	../../Crypto.h ../../Datagram.h ../../Destination.h ../../Family.h ../../FS.h \
	../../Garlic.h ../../HTTP.h ../../HTTPProxy.h ../../I2CP.h ../../I2NPProtocol.h \
	../../I2PEndian.h ../../I2PService.h ../../I2PTunnel.h ../../Identity.h ../../LeaseSet.h \
	../../LittleBigEndian.h ../../Log.h ../../NetDb.h ../../NetDbRequests.h ../../NTCPSession.h \
	../../Profiling.h ../../Queue.h ../../Reseed.h ../../RouterContext.h ../../RouterInfo.h \
	../../SAM.h ../../Signature.h ../../SOCKS.h ../../SSU.h ../../SSUData.h ../../SSUSession.h \
	../../Streaming.h ../../Timestamp.h ../../TransitTunnel.h ../../Transports.h \
	../../TransportSession.h ../../Tunnel.h ../../TunnelBase.h ../../TunnelConfig.h \
	../../TunnelEndpoint.h ../../TunnelGateway.h ../../TunnelPool.h ../../UPnP.h \
	../../util.h ../../version.h ../../Gzip.h ../../Tag.h \
	../../BloomFiler.h ../../Event.h ../../Gost.h ../../MatchedDestination.h

FORMS += mainwindow.ui

CONFIG += mobility

MOBILITY =

LIBS += -lz

android {
	message("Using Android settings")
	DEFINES += ANDROID=1
	DEFINES += __ANDROID__

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
