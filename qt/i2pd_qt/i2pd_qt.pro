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

SOURCES += DaemonQT.cpp mainwindow.cpp
#	../../HTTPServer.cpp ../../I2PControl.cpp ../../Daemon.cpp ../../Config.cpp \
#	../../AddressBook.cpp ../../api.cpp ../../Base.cpp ../../BOB.cpp ../../ClientContext.cpp \
#	../../Crypto.cpp ../../Datagram.cpp ../../Destination.cpp ../../Family.cpp ../../FS.cpp \
#	../../Garlic.cpp ../../HTTP.cpp ../../HTTPProxy.cpp ../../I2CP.cpp ../../I2NPProtocol.cpp \
#	../../I2PEndian.cpp ../../I2PService.cpp ../../I2PTunnel.cpp ../../Identity.cpp \
#	../../LeaseSet.cpp ../../Log.cpp ../../NetDb.cpp ../../NetDbRequests.cpp \
#	../../NTCPSession.cpp ../../Profiling.cpp ../../Reseed.cpp ../../RouterContext.cpp \
#	../../RouterInfo.cpp ../../SAM.cpp ../../Signature.cpp ../../SOCKS.cpp ../../SSU.cpp \
#	../../SSUData.cpp ../../SSUSession.cpp ../../Streaming.cpp ../../TransitTunnel.cpp \
#	../../Transports.cpp ../../Tunnel.cpp ../../TunnelEndpoint.cpp ../../TunnelGateway.cpp \
#	../../TunnelPool.cpp ../../UPnP.cpp ../../Gzip.cpp ../../Timestamp.cpp ../../util.cpp \
#	../../Event.cpp ../../BloomFiler.cpp ../../Gost.cpp ../../MatchedDestination.cpp \
#	../../i2pd.cpp

SOURCES += $$files(../../libi2pd/*.cpp)
SOURCES += $$files(../../libi2pd_client/*.cpp)
SOURCES += $$files(../../daemon/*.cpp)
SOURCES += $$files(./*.cpp)

SOURCES -= ../../daemon/UnixDaemon.cpp

HEADERS  += DaemonQT.h mainwindow.h
#	../../HTTPServer.h ../../I2PControl.h ../../UPnP.h ../../Daemon.h ../../Config.h \
#	../../AddressBook.h ../../api.h ../../Base.h ../../BOB.h ../../ClientContext.h \
#	../../Crypto.h ../../Datagram.h ../../Destination.h ../../Family.h ../../FS.h \
#	../../Garlic.h ../../HTTP.h ../../HTTPProxy.h ../../I2CP.h ../../I2NPProtocol.h \
#	../../I2PEndian.h ../../I2PService.h ../../I2PTunnel.h ../../Identity.h ../../LeaseSet.h \
#	../../LittleBigEndian.h ../../Log.h ../../NetDb.h ../../NetDbRequests.h ../../NTCPSession.h \
#	../../Profiling.h ../../Queue.h ../../Reseed.h ../../RouterContext.h ../../RouterInfo.h \
#	../../SAM.h ../../Signature.h ../../SOCKS.h ../../SSU.h ../../SSUData.h ../../SSUSession.h \
#	../../Streaming.h ../../Timestamp.h ../../TransitTunnel.h ../../Transports.h \
#	../../TransportSession.h ../../Tunnel.h ../../TunnelBase.h ../../TunnelConfig.h \
#	../../TunnelEndpoint.h ../../TunnelGateway.h ../../TunnelPool.h ../../UPnP.h \
#	../../util.h ../../version.h ../../Gzip.h ../../Tag.h \
#	../../BloomFiler.h ../../Event.h ../../Gost.h ../../MatchedDestination.h

INCLUDEPATH += ../../libi2pd
INCLUDEPATH += ../../libi2pd_client
INCLUDEPATH += ../../daemon
INCLUDEPATH += .

FORMS += mainwindow.ui \
    tunnelform.ui

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

DISTFILES += \
    ../../android/bin/classes.dex \
    ../../android/bin/I2PD.apk \
    ../../android/bin/AndroidManifest.xml \
    ../../android/AndroidManifest.xml \
    ../../libi2pd.a \
    ../../libi2pdclient.a \
    ../../i2pd \
    ../../android/bin/classes/org/purplei2p/i2pd/BuildConfig.class \
    ../../android/bin/classes/org/purplei2p/i2pd/DaemonSingleton$1.class \
    ../../android/bin/classes/org/purplei2p/i2pd/DaemonSingleton$State.class \
    ../../android/bin/classes/org/purplei2p/i2pd/DaemonSingleton$StateChangeListener.class \
    ../../android/bin/classes/org/purplei2p/i2pd/DaemonSingleton.class \
    ../../android/bin/classes/org/purplei2p/i2pd/ForegroundService$LocalBinder.class \
    ../../android/bin/classes/org/purplei2p/i2pd/ForegroundService.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD$1$1.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD$1.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD$2.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD$3$1.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD$3.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD.class \
    ../../android/bin/classes/org/purplei2p/i2pd/I2PD_JNI.class \
    ../../android/bin/classes/org/purplei2p/i2pd/NetworkStateChangeReceiver.class \
    ../../android/bin/classes/org/purplei2p/i2pd/R$attr.class \
    ../../android/bin/classes/org/purplei2p/i2pd/R$drawable.class \
    ../../android/bin/classes/org/purplei2p/i2pd/R$id.class \
    ../../android/bin/classes/org/purplei2p/i2pd/R$menu.class \
    ../../android/bin/classes/org/purplei2p/i2pd/R$string.class \
    ../../android/bin/classes/org/purplei2p/i2pd/R.class \
    ../../android/bin/dexedLibs/android-support-v4-bddf40bf5b9bc79d6d6d4419e6234206.jar \
    ../../android/libs/android-support-v4.jar \
    android/libs/android-support-v4.jar \
    ../../debian/i2pd.init \
    ../../debian/postinst \
    ../../debian/postrm \
    ../../entrypoint.sh \
    ../../contrib/certificates/family/i2p-dev.crt \
    ../../contrib/certificates/family/i2pd-dev.crt \
    ../../contrib/certificates/family/mca2-i2p.crt \
    ../../contrib/certificates/family/volatile.crt \
    ../../contrib/certificates/reseed/atomike_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/backup_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/bugme_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/echelon_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/hottuna_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/meeh_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/parg_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/r4sas_at_mail.i2p.crt \
    ../../contrib/certificates/reseed/zmx_at_mail.i2p.crt \
    ../../contrib/certificates/router/killyourtv_at_mail.i2p.crt \
    ../../contrib/certificates/router/orignal_at_mail.i2p.crt \
    ../../contrib/certificates/router/str4d_at_mail.i2p.crt \
    ../../contrib/certificates/router/zzz_at_mail.i2p.crt \
    ../../build/fig.yml \
    ../../appveyor.yml \
    ../../android/res/menu/options_main.xml \
    ../../android/res/values/strings.xml \
    ../../android/build.xml \
    android/res/layout/splash.xml \
    android/res/values/libs.xml \
    android/res/values/strings.xml \
    android/res/values-de/strings.xml \
    android/res/values-el/strings.xml \
    android/res/values-es/strings.xml \
    android/res/values-et/strings.xml \
    android/res/values-fa/strings.xml \
    android/res/values-fr/strings.xml \
    android/res/values-id/strings.xml \
    android/res/values-it/strings.xml \
    android/res/values-ja/strings.xml \
    android/res/values-ms/strings.xml \
    android/res/values-nb/strings.xml \
    android/res/values-nl/strings.xml \
    android/res/values-pl/strings.xml \
    android/res/values-pt-rBR/strings.xml \
    android/res/values-ro/strings.xml \
    android/res/values-rs/strings.xml \
    android/res/values-ru/strings.xml \
    android/res/values-zh-rCN/strings.xml \
    android/res/values-zh-rTW/strings.xml \
    ../../android/bin/resources.ap_ \
    ../../Win32/ictoopie.bmp \
    ../../Win32/mask.bmp \
    ../../android/bin/res/crunch/drawable/icon.png \
    ../../android/bin/res/crunch/drawable/itoopie_notification_icon.png \
    ../../android/res/drawable/icon.png \
    ../../android/res/drawable/itoopie_notification_icon.png \
    ../../docs/itoopieImage.png \
    android/res/drawable/itoopie_notification_icon.png \
    android/res/drawable-hdpi/icon.png \
    ../../Win32/ictoopie.ico \
    ../../Win32/mask.ico \
    docs/patch_openssl_so_libs.html \
    ../../android/bin/jarlist.cache \
    ../../android/jni/Android.mk \
    ../../android/jni/Application.mk \
    ../../android/proguard-project.txt \
    ../../android/project.properties \
    ../../build/cmake_modules/NSIS.template.in \
    ../../build/docker/old-ubuntu-based/Dockerfile \
    ../../contrib/debian/i2pd.service \
    ../../contrib/debian/i2pd.tmpfile \
    ../../contrib/rpm/i2pd.service \
    ../../debian/patches/series \
    ../../debian/source/format \
    ../../debian/compat \
    ../../debian/control \
    ../../debian/copyright \
    ../../debian/docs \
    ../../debian/i2pd.1 \
    ../../debian/i2pd.default \
    ../../debian/i2pd.dirs \
    ../../debian/i2pd.install \
    ../../debian/i2pd.links \
    ../../debian/i2pd.manpages \
    ../../debian/i2pd.openrc \
    ../../debian/i2pd.upstart \
    ../../debian/logrotate \
    ../../debian/watch \
    ../../docs/Doxyfile \
    ../../docs/index.rst \
    ../../docs/subscriptions.txt \
    ../../docs/tunnels.conf \
    android/src/org/kde/necessitas/ministro/IMinistro.aidl \
    android/src/org/kde/necessitas/ministro/IMinistroCallback.aidl \
    android/build.gradle \
    android/project.properties \
    ../../Win32/nsi/helper_readme.nsh \
    ../../Win32/nsi/servicelib.nsh \
    ../../Win32/i2pd.sln \
    ../../Win32/i2pd.vcxproj \
    ../../Win32/i2pd.vcxproj.filters \
    ../../Win32/inno_installer.iss \
    ../../Win32/install_service.bat \
    ../../Win32/installer.iss \
    ../../Win32/Itoopie.cmd \
    ../../Win32/PurpleI2P.nsi \
    ../../Win32/uninstall_service.bat \
    ../../Dockerfile \
    ../../filelist.mk \
    ../../LICENSE \
    ../../debian/changelog \
    ../../ChangeLog \
    ../../build/cmake_modules/FindMiniUPnPc.cmake \
    ../../build/CMakeLists.txt \
    ../../android/gen/org/purplei2p/i2pd/BuildConfig.java \
    ../../android/gen/org/purplei2p/i2pd/R.java \
    ../../android/src/org/purplei2p/i2pd/DaemonSingleton.java \
    ../../android/src/org/purplei2p/i2pd/ForegroundService.java \
    ../../android/src/org/purplei2p/i2pd/I2PD.java \
    ../../android/src/org/purplei2p/i2pd/I2PD_JNI.java \
    ../../android/src/org/purplei2p/i2pd/NetworkStateChangeReceiver.java \
    android/src/org/purplei2p/i2pd/I2PDMainActivity.java \
    android/src/org/purplei2p/i2pd/LocalService.java \
    android/src/org/qtproject/qt5/android/bindings/QtActivity.java \
    android/src/org/qtproject/qt5/android/bindings/QtApplication.java \
    ../../debian/rules \
    ../../build/docker/README.md \
    ../../docs/building/android.md \
    ../../docs/building/cross.md \
    ../../docs/building/ios.md \
    ../../docs/building/requirements.md \
    ../../docs/building/unix.md \
    ../../docs/building/windows.md \
    ../../docs/config_opts_after_2.3.0.md \
    ../../docs/configuration.md \
    ../../docs/family.md \
    ../../docs/hacking.md \
    ../../docs/usage.md \
    README.md \
    ../../README.md \
    ../../docs/i2pd.conf \
    ../../build/cmake-zlib-amd64.patch \
    ../../build/cmake-zlib-static.patch \
    ../../debian/patches/01-tune-build-opts.patch \
    ../../docs/conf.py \
    ../../contrib/debian/README \
    ../../contrib/rpm/i2pd.spec
