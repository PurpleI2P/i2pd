UNAME := $(shell uname -s)

ifeq ($(UNAME),Darwin)
	include Makefile.osx
else ifeq ($(UNAME), FreeBSD)
	include Makefile.bsd
else
	include Makefile.linux
endif

