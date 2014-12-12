UNAME := $(shell uname -s)
SHLIB := libi2pd.so
I2PD  := i2p

include filelist.mk

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
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(CPU_FLAGS) -c -o $@ $<

obj/%.o : %.cpp %.h
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(CPU_FLAGS) -c -o $@ $<

$(I2PD):  $(patsubst %.cpp,obj/%.o,$(DAEMON_SRC))
	$(CXX) -o $@ $^ $(LDLIBS) $(LDFLAGS) $(LIBS)

$(SHLIB): $(patsubst %.cpp,obj/%.o,$(LIB_SRC))
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(CPU_FLAGS) -shared -o $@ $^

clean:
	rm -fr obj $(I2PD) $(SHLIB)

.PHONY: all
.PHONY: clean
