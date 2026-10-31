#
# I2PD trunk

include $(TOPDIR)/rules.mk

PKG_NAME:=i2pd

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/PurpleI2P/i2pd
PKG_SOURCE_DATE:=2026-10-30
PKG_SOURCE_VERSION:=6b214f74d2c1b9d892cda29119f0942097cbfd85
PKG_MIRROR_HASH:=4d58ca9cf143a24f04685615d1d1487d471dfa8855a8e5194d5ff28db5a95337
# PKG_MIRROR_HASH:=skip
PKG_RELEASE:=1

PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=lto
PKG_CONFIG_DEPENDS:= CONFIG_I2PD_ENABLE_TORRENT_CLIENT CONFIG_I2PD_ENABLE_UPNP CONFIG_I2PD_ENABLE_UI_TRANSLATIONS
PKG_BUILD_DEPENDS:= boost zlib openssl I2PD_ENABLE_UPNP:miniupnpc

include $(INCLUDE_DIR)/package.mk

define Package/i2pd
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:= +libopenssl \
            +boost +boost-program_options \
            +I2PD_ENABLE_TORRENT_CLIENT:boost-json +I2PD_ENABLE_TORRENT_CLIENT:boost-url \
            +I2PD_ENABLE_UPNP:libminiupnpc +zlib
  TITLE:=Full-featured C++ implementation of I2P client
  URL:=https://github.com/PurpleI2P/i2pd/
  MAINTAINER:=
  USERID:=i2pd:i2pd
endef

GIT_VERSION:= git~$(shell printf '%.8s' $(PKG_SOURCE_VERSION))
EXTRA_CFLAGS:= -DGITVER=$(GIT_VERSION)

define Package/i2pd/config
  source "$(SOURCE)/Config.in"
endef

$(shell rm -f ./patches/002-enable-upnp.patch)
ifeq ($(CONFIG_I2PD_ENABLE_UPNP),y)
  $(shell $(CP) ./files/002-enable-upnp.patch ./patches)
endif

$(shell rm -f ./patches/003-disable-torrents.patch)
ifneq ($(CONFIG_I2PD_ENABLE_TORRENT_CLIENT),y)
  $(shell $(CP) ./files/003-disable-torrents.patch ./patches)
endif

# TODO
# ifneq ($(CONFIG_I2PD_ENABLE_UI_TRANSLATIONS),y)
# ifeq ($(CONFIG_I2PD_ENABLE_UI_TRANSLATIONS),y)
#   $(shell :)
# endif

define Package/i2pd/description
  I2P (Invisible Internet Protocol) is a universal anonymous network layer.
  All communications over I2P are anonymous and end-to-end encrypted,
  participants don't reveal their real IP addresses.
endef

define Package/i2pd/conffiles
/etc/i2pd.conf
/etc/i2pd_tunnels.conf
/etc/i2pd_tunnels.d/*
endef

define Package/i2pd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/i2pd $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/i2pd.init $(1)/etc/init.d/i2pd
	$(INSTALL_DIR) $(1)/etc/i2pd
	$(INSTALL_DATA) ./files/i2pd.conf $(1)/etc/i2pd
	$(INSTALL_DIR) $(1)/etc/i2pd/tunnels.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/tunnels.conf  $(1)/etc/i2pd
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/tunnels.d/*.conf  $(1)/etc/i2pd/tunnels.d
	$(INSTALL_DIR) $(1)/usr/share/i2pd
	$(CP) $(PKG_BUILD_DIR)/contrib/certificates  $(1)/usr/share/i2pd
endef

$(eval $(call BuildPackage,i2pd))

