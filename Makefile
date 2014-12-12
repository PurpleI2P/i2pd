UNAME := $(shell uname -s)
SHLIB := libi2pd.so
I2PD  := i2p

include filelist.mk

USE_AESNI  := yes
USE_STATIC := no

ifeq ($(UNAME),Darwin)
  DAEMON_SRC += DaemonLinux.cpp
	include Makefile.osx
else ifeq ($(UNAME),FreeBSD)
  DAEMON_SRC += DaemonLinux.cpp
	include Makefile.bsd
else ifeq ($(UNAME),Linux)
  DAEMON_SRC += DaemonLinux.cpp
	include Makefile.linux
else # win32
  DAEMON_SRC += DaemonWin32.cpp
endif

all: obj $(SHLIB) $(I2PD)

obj:
	mkdir -p obj

# weaker rule for building files without headers
obj/%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(INCFLAGS) -c -o $@ $<

obj/%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $(INCFLAGS) -c -o $@ $<

$(I2PD):  $(patsubst %.cpp,obj/%.o,$(DAEMON_SRC))
	$(CXX) -o $@ $(LDLIBS) $(LDFLAGS) $^

$(SHLIB): $(patsubst %.cpp,obj/%.o,$(LIB_SRC))
	$(CXX) -o $@ -shared $(CXXFLAGS) $(INCFLAGS) $^

clean:
	rm -fr obj $(I2PD) $(SHLIB)

.PHONY: all
.PHONY: clean
