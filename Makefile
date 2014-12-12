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

.SUFFIXES:
.SUFFIXES:	.c .cc .C .cpp .o

obj/%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(CPU_FLAGS) -c -o $@ $<

obj:
	mkdir -p obj

$(I2PD):  $(OBJECTS:obj/%=obj/%)
	$(CXX) -o $@ $^ $(LDLIBS) $(LDFLAGS) $(LIBS)

$(SHLIB): $(OBJECTS:obj/%=obj/%) api.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(CPU_FLAGS) -shared -o $@ $^

clean:
	rm -fr obj $(I2PD) $(SHLIB)

.PHONY: all
.PHONY: clean
