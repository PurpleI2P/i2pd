
UNAME := $(shell uname -s)

ifeq ($(UNAME),Darwin)
	include Makefile.osx
else
	include Makefile.linux
endif

