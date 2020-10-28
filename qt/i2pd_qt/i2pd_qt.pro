QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = i2pd_qt
TEMPLATE = app
QMAKE_CXXFLAGS *= -Wno-unused-parameter -Wno-maybe-uninitialized
CONFIG += strict_c++ c++11

CONFIG(debug, debug|release) {
    message(Debug build)
    DEFINES += DEBUG_WITH_DEFAULT_LOGGING
} else {
    message(Release build)
}

SOURCES += DaemonQT.cpp mainwindow.cpp \
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
    SaverImpl.cpp \
    ../../daemon/Daemon.cpp \
    ../../daemon/HTTPServer.cpp \
    ../../daemon/I2PControl.cpp \
    ../../daemon/i2pd.cpp \
    ../../daemon/UPnP.cpp

HEADERS  += DaemonQT.h mainwindow.h \
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
    SaverImpl.h \
    ../../daemon/Daemon.h \
    ../../daemon/HTTPServer.h \
    ../../daemon/I2PControl.h \
    ../../daemon/UPnP.h


INCLUDEPATH += ../../libi2pd
INCLUDEPATH += ../../libi2pd_client
INCLUDEPATH += ../../daemon
INCLUDEPATH += .

FORMS += mainwindow.ui \
    tunnelform.ui \
    statusbuttons.ui \
    routercommandswidget.ui \
    generalsettingswidget.ui

LIBS += $$PWD/../../libi2pd.a $$PWD/../../libi2pdclient.a -lz

libi2pd.commands = cd $$PWD/../../ && mkdir -p obj/libi2pd && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) USE_AVX=no USE_AESNI=no USE_UPNP=yes DEBUG=no api
libi2pd.target = $$PWD/../../libi2pd.a
libi2pd.depends = FORCE

libi2pdclient.commands = cd $$PWD/../../ && mkdir -p obj/libi2pd_client && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) USE_AVX=no USE_AESNI=no USE_UPNP=yes DEBUG=no api_client
libi2pdclient.target = $$PWD/../../libi2pdclient.a
libi2pdclient.depends = FORCE

cleani2pd.commands = cd $$PWD/../../ && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) clean
cleani2pd.depends = clean

PRE_TARGETDEPS += $$PWD/../../libi2pd.a $$PWD/../../libi2pdclient.a
QMAKE_EXTRA_TARGETS += cleani2pd libi2pd libi2pdclient
CLEAN_DEPS += cleani2pd


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

        # linker's -s means "strip"
        QMAKE_LFLAGS_RELEASE += -s

        LIBS = \
        $$PWD/../../libi2pd.a $$PWD/../../libi2pdclient.a \
        -lminiupnpc \
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

