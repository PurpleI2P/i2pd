UNAME := $(shell uname -s)

ifeq ($(UNAME),Darwin)
	include Makefile.osx
else ifeq ($(UNAME), FreeBSD)
	include Makefile.bsd
else
	include Makefile.linux
endif

all: obj i2p

i2p: $(OBJECTS:obj/%=obj/%)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

.SUFFIXES:
.SUFFIXES:	.c .cc .C .cpp .o

obj/%.o : %.cpp
	$(CC) -o $@ $< -c $(CFLAGS) $(INCFLAGS) $(CPU_FLAGS)

obj:
	mkdir -p obj

clean:
	rm -fr obj i2p

.PHONY: all
.PHONY: clean
