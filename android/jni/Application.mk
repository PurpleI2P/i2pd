#APP_ABI := all
#APP_ABI := armeabi-v7a x86
#APP_ABI := x86
#APP_ABI := x86_64
APP_ABI := armeabi-v7a
#can be android-3 but will fail for x86 since arch-x86 is not present at ndkroot/platforms/android-3/ . libz is taken from there.
APP_PLATFORM := android-14

# http://stackoverflow.com/a/21386866/529442 http://stackoverflow.com/a/15616255/529442 to enable c++11 support in Eclipse
NDK_TOOLCHAIN_VERSION := 4.9
# APP_STL := stlport_shared  --> does not seem to contain C++11 features
APP_STL := gnustl_shared

# Enable c++11 extentions in source code
APP_CPPFLAGS += -std=c++11

APP_CPPFLAGS += -DANDROID -D__ANDROID__ -DUSE_UPNP
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
APP_CPPFLAGS += -DANDROID_ARM7A
endif

APP_OPTIM  := debug

# git clone https://github.com/PurpleI2P/Boost-for-Android-Prebuilt.git
# git clone https://github.com/PurpleI2P/OpenSSL-for-Android-Prebuilt.git
# git clone https://github.com/PurpleI2P/MiniUPnP-for-Android-Prebuilt.git
# git clone https://github.com/PurpleI2P/android-ifaddrs.git
# change to your own
I2PD_LIBS_PATH = /path/to/libraries
BOOST_PATH = $(I2PD_LIBS_PATH)/Boost-for-Android-Prebuilt
OPENSSL_PATH = $(I2PD_LIBS_PATH)/OpenSSL-for-Android-Prebuilt
MINIUPNP_PATH = $(I2PD_LIBS_PATH)/MiniUPnP-for-Android-Prebuilt
IFADDRS_PATH = $(I2PD_LIBS_PATH)/android-ifaddrs

# don't change me
I2PD_SRC_PATH = $(PWD)/..

LIB_SRC_PATH = $(I2PD_SRC_PATH)/libi2pd
LIB_CLIENT_SRC_PATH = $(I2PD_SRC_PATH)/libi2pd_client
DAEMON_SRC_PATH = $(I2PD_SRC_PATH)/daemon
