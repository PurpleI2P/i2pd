LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := i2pd
LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_C_INCLUDES += $(IFADDRS_PATH) ../..
LOCAL_STATIC_LIBRARIES := \
	boost_system \
	boost_date_time \
	boost_filesystem \
	boost_program_options \
	crypto ssl \
	miniupnpc
LOCAL_LDLIBS := -lz

LOCAL_SRC_FILES := DaemonAndroid.cpp i2pd_android.cpp \
	$(IFADDRS_PATH)/ifaddrs.c \
    ../../HTTPServer.cpp ../../I2PControl.cpp ../../Daemon.cpp ../../Config.cpp \
    ../../AddressBook.cpp \
    ../../api.cpp \
    ../../Base.cpp \
    ../../BOB.cpp \
    ../../ClientContext.cpp \
    ../../Crypto.cpp \
    ../../Datagram.cpp \
    ../../Destination.cpp \
    ../../Family.cpp \
    ../../FS.cpp \
    ../../Garlic.cpp \
    ../../Gzip.cpp \
    ../../HTTP.cpp \
    ../../HTTPProxy.cpp \
    ../../I2CP.cpp \
    ../../I2NPProtocol.cpp \
    ../../I2PEndian.cpp \
    ../../I2PService.cpp \
    ../../I2PTunnel.cpp \
    ../../Identity.cpp \
    ../../LeaseSet.cpp \
    ../../Log.cpp \
    ../../NetDb.cpp \
    ../../NetDbRequests.cpp \
    ../../NTCPSession.cpp \
    ../../Profiling.cpp \
    ../../Reseed.cpp \
    ../../RouterContext.cpp \
    ../../RouterInfo.cpp \
    ../../SAM.cpp \
    ../../Signature.cpp \
    ../../SOCKS.cpp \
    ../../SSU.cpp \
    ../../SSUData.cpp \
    ../../SSUSession.cpp \
    ../../Streaming.cpp \
    ../../TransitTunnel.cpp \
    ../../Transports.cpp \
    ../../Tunnel.cpp \
    ../../TunnelEndpoint.cpp \
    ../../TunnelGateway.cpp \
    ../../TunnelPool.cpp \
	../../Timestamp.cpp \
	../../Event.cpp \
	../../Gost.cpp \
	../../WebSocks.cpp \
	../../BloomFilter.cpp \
	../../MatchedDestination.cpp \
    ../../util.cpp \
     ../../i2pd.cpp ../../UPnP.cpp

include $(BUILD_SHARED_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := boost_system
LOCAL_SRC_FILES := $(BOOST_PATH)/boost_1_62_0/$(TARGET_ARCH_ABI)/lib/libboost_system.a
LOCAL_EXPORT_C_INCLUDES := $(BOOST_PATH)/boost_1_62_0/include
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := boost_date_time
LOCAL_SRC_FILES := $(BOOST_PATH)/boost_1_62_0/$(TARGET_ARCH_ABI)/lib/libboost_date_time.a
LOCAL_EXPORT_C_INCLUDES := $(BOOST_PATH)/boost_1_62_0/include
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := boost_filesystem
LOCAL_SRC_FILES := $(BOOST_PATH)/boost_1_62_0/$(TARGET_ARCH_ABI)/lib/libboost_filesystem.a
LOCAL_EXPORT_C_INCLUDES := $(BOOST_PATH)/boost_1_62_0/include
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := boost_program_options
LOCAL_SRC_FILES := $(BOOST_PATH)/boost_1_62_0/$(TARGET_ARCH_ABI)/lib/libboost_program_options.a
LOCAL_EXPORT_C_INCLUDES := $(BOOST_PATH)/boost_1_62_0/include
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := crypto
LOCAL_SRC_FILES := $(OPENSSL_PATH)/openssl-1.1.0e/$(TARGET_ARCH_ABI)/lib/libcrypto.a
LOCAL_EXPORT_C_INCLUDES := $(OPENSSL_PATH)/openssl-1.1.0e/include
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := ssl
LOCAL_SRC_FILES := $(OPENSSL_PATH)/openssl-1.1.0e/$(TARGET_ARCH_ABI)/lib/libssl.a
LOCAL_EXPORT_C_INCLUDES := $(OPENSSL_PATH)/openssl-1.1.0e/include
LOCAL_STATIC_LIBRARIES := crypto
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := miniupnpc
LOCAL_SRC_FILES := $(MINIUPNP_PATH)/miniupnp-2.0/$(TARGET_ARCH_ABI)/lib/libminiupnpc.a
LOCAL_EXPORT_C_INCLUDES := $(MINIUPNP_PATH)/miniupnp-2.0/include
include $(PREBUILT_STATIC_LIBRARY)
