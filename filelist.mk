LIB_SRC = $(wildcard $(LIB_SRC_DIR)/*.cpp)
LIB_CLIENT_SRC = $(wildcard $(LIB_CLIENT_SRC_DIR)/*.cpp)
LANG_SRC = $(wildcard $(LANG_SRC_DIR)/*.cpp)
WEBCONSOLE_SRC = $(wildcard $(WEBCONSOLE_SRC_DIR)/*.cpp)

WRAP_LIB_SRC = $(wildcard $(WRAP_SRC_DIR)/*.cpp)
DAEMON_SRC = $(DAEMON_SRC_DIR)/Daemon.cpp $(DAEMON_SRC_DIR)/I2PControl.cpp $(DAEMON_SRC_DIR)/i2pd.cpp $(DAEMON_SRC_DIR)/UPnP.cpp
