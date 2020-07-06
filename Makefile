SYS := $(shell $(CXX) -dumpmachine)
SHLIB := libi2pd.so
ARLIB := libi2pd.a
SHLIB_CLIENT := libi2pdclient.so
ARLIB_CLIENT := libi2pdclient.a
I2PD := i2pd
GREP := grep
DEPS := obj/make.dep

LIB_SRC_DIR := libi2pd
LIB_CLIENT_SRC_DIR := libi2pd_client
DAEMON_SRC_DIR := daemon

include filelist.mk

USE_AESNI	:= yes
USE_AVX		:= yes
USE_STATIC	:= no
USE_MESHNET	:= no
USE_UPNP	:= no
DEBUG		:= yes

ifeq ($(DEBUG),yes)
	CXX_DEBUG = -g
else
	CXX_DEBUG = -Os
	LD_DEBUG = -s
endif

ifneq (, $(findstring darwin, $(SYS)))
	DAEMON_SRC += $(DAEMON_SRC_DIR)/UnixDaemon.cpp
	ifeq ($(HOMEBREW),1)
		include Makefile.homebrew
	else
		include Makefile.osx
	endif
else ifneq (, $(findstring linux, $(SYS))$(findstring gnu, $(SYS)))
	DAEMON_SRC += $(DAEMON_SRC_DIR)/UnixDaemon.cpp
	include Makefile.linux
else ifneq (, $(findstring freebsd, $(SYS))$(findstring openbsd, $(SYS)))
	DAEMON_SRC += $(DAEMON_SRC_DIR)/UnixDaemon.cpp
	include Makefile.bsd
else ifneq (, $(findstring mingw, $(SYS))$(findstring cygwin, $(SYS)))
	DAEMON_SRC += Win32/DaemonWin32.cpp Win32/Win32Service.cpp Win32/Win32App.cpp Win32/Win32NetState.cpp
	include Makefile.mingw
else # not supported
	$(error Not supported platform)
endif

ifeq ($(USE_MESHNET),yes)
	NEEDED_CXXFLAGS += -DMESHNET
endif

NEEDED_CXXFLAGS += -I$(LIB_SRC_DIR) -I$(LIB_CLIENT_SRC_DIR)

all: mk_obj_dir $(ARLIB) $(ARLIB_CLIENT) $(I2PD)

mk_obj_dir:
	@mkdir -p obj
	@mkdir -p obj/Win32
	@mkdir -p obj/$(LIB_SRC_DIR)
	@mkdir -p obj/$(LIB_CLIENT_SRC_DIR)
	@mkdir -p obj/$(DAEMON_SRC_DIR)

api: mk_obj_dir $(SHLIB) $(ARLIB)
api_client: mk_obj_dir $(SHLIB) $(ARLIB) $(SHLIB_CLIENT) $(ARLIB_CLIENT)

## NOTE: The NEEDED_CXXFLAGS are here so that CXXFLAGS can be specified at build time
## **without** overwriting the CXXFLAGS which we need in order to build.
## For example, when adding 'hardening flags' to the build
## (e.g. -fstack-protector-strong -Wformat -Werror=format-security), we do not want to remove
## -std=c++11. If you want to remove this variable please do so in a way that allows setting
## custom FLAGS to work at build-time.

deps: mk_obj_dir
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) -MM *.cpp > $(DEPS)
	@sed -i -e '/\.o:/ s/^/obj\//' $(DEPS)

obj/%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(CPU_FLAGS) -c -o $@ $<

# '-' is 'ignore if missing' on first run
-include $(DEPS)

DAEMON_OBJS += $(patsubst %.cpp,obj/%.o,$(DAEMON_SRC))
$(I2PD): $(DAEMON_OBJS) $(ARLIB) $(ARLIB_CLIENT)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(SHLIB): $(patsubst %.cpp,obj/%.o,$(LIB_SRC))
ifneq ($(USE_STATIC),yes)
	$(CXX) $(LDFLAGS) $(LDLIBS) -shared -o $@ $^
endif

$(SHLIB_CLIENT): $(patsubst %.cpp,obj/%.o,$(LIB_CLIENT_SRC))
	$(CXX) $(LDFLAGS) $(LDLIBS) -shared -o $@ $^

$(ARLIB): $(patsubst %.cpp,obj/%.o,$(LIB_SRC))
	$(AR) -r $@ $^

$(ARLIB_CLIENT): $(patsubst %.cpp,obj/%.o,$(LIB_CLIENT_SRC))
	$(AR) -r $@ $^

clean:
	$(RM) -r obj
	$(RM) -r docs/generated
	$(RM) $(I2PD) $(SHLIB) $(ARLIB) $(SHLIB_CLIENT) $(ARLIB_CLIENT)

strip: $(I2PD) $(SHLIB_CLIENT) $(SHLIB)
	strip $^

LATEST_TAG=$(shell git describe --tags --abbrev=0 openssl)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
dist:
	git archive --format=tar.gz -9 --worktree-attributes \
	    --prefix=i2pd_$(LATEST_TAG)/ $(LATEST_TAG) -o i2pd_$(LATEST_TAG).tar.gz

last-dist:
	git archive --format=tar.gz -9 --worktree-attributes \
	    --prefix=i2pd_$(LATEST_TAG)/ $(BRANCH) -o ../i2pd_$(LATEST_TAG).orig.tar.gz

doxygen:
	doxygen -s docs/Doxyfile

.PHONY: all
.PHONY: clean
.PHONY: deps
.PHONY: doxygen
.PHONY: dist
.PHONY: last-dist
.PHONY: api
.PHONY: api_client
.PHONY: mk_obj_dir
.PHONY: install
