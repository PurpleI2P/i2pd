UNAME := $(shell uname -s)

ifeq ($(UNAME),Darwin)
	include ../Makefile.osx
else ifeq ($(UNAME), FreeBSD)
	include ../Makefile.bsd
else
	include ../Makefile.linux
endif

SHARED_LIB = libi2pd.so
all: obj $(SHARED_LIB)

$(SHARED_LIB): $(OBJECTS:obj/%=obj/%)
	$(CXX) -shared -o $(SHARED_LIB) $^

.SUFFIXES:
.SUFFIXES:	.c .cc .C .cpp .o

obj/%.o : ../%.cpp
	$(CXX) -o $@ $< -c $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -I.. -fPIC $(CPU_FLAGS)

obj/api.o: api.cpp
	$(CXX) -o obj/api.o api.cpp -c $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -I.. -fPIC $(CPU_FLAGS)

obj:
	mkdir -p obj

clean:
	rm -fr obj $(SHARED_LIB)

.PHONY: all
.PHONY: clean
