#APP_ABI := armeabi-v7a x86
#APP_PLATFORM := android-14

# ABI arm64-v8a and x86_64 supported only from platform-21
#APP_ABI := arm64-v8a x86_64
#APP_PLATFORM := android-21

NDK_TOOLCHAIN_VERSION := clang
#APP_STL := c++_shared
APP_STL := c++_static

# Enable c++17 extensions in source code
APP_CPPFLAGS += -std=c++17 -fexceptions -frtti

APP_CPPFLAGS += -DANDROID -D__ANDROID__ -DUSE_UPNP
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
APP_CPPFLAGS += -DANDROID_ARM7A
endif

# git clone https://github.com/PurpleI2P/Boost-for-Android-Prebuilt.git -b boost-1_72_0
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
