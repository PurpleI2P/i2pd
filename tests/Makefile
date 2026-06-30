SYS := $(shell $(CXX) -dumpmachine)

CXXFLAGS += -Wall -Wno-unused-parameter -Wextra -pedantic -O0 -g -std=c++17 -D_GLIBCXX_USE_NANOSLEEP=1 -DOPENSSL_SUPPRESS_DEPRECATED -pthread -Wl,--unresolved-symbols=ignore-in-object-files
INCFLAGS += -I../libi2pd -I../libi2pd_client

LIBI2PD = ../libi2pd.a
LIBI2PD_CLIENT = ../libi2pdclient.a

TESTS = \
	test-http-merge_chunked test-http-req test-http-res test-http-url test-http-url_decode \
	test-gost test-gost-sig test-base-64 test-aeadchacha20poly1305 test-blinding \
	test-elligator test-eddsa test-aes test-address-mapper

ifneq (, $(findstring mingw, $(SYS))$(findstring windows-gnu, $(SYS))$(findstring cygwin, $(SYS)))
	CXXFLAGS += -DWIN32_LEAN_AND_MEAN
	LDFLAGS += -mwindows -static
	BOOST_SUFFIX = -mt
	NEEDED_LDLIBS = -lwsock32 -lws2_32 -lgdi32 -liphlpapi -lole32
endif

LDLIBS = \
	-lboost_system$(BOOST_SUFFIX) \
	-lboost_program_options$(BOOST_SUFFIX) \
	-lssl \
	-lcrypto \
	-lz \
	$(NEEDED_LDLIBS) \
	-lpthread


all: $(TESTS) run

$(LIBI2PD):
	@echo "Building libi2pd.a ..." && cd .. && $(MAKE) libi2pd.a

$(LIBI2PD_CLIENT):
	@echo "Building libi2pdclient.a ..." && cd .. && $(MAKE) libi2pdclient.a

test-http-%: test-http-%.cpp $(LIBI2PD)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-base-%: test-base-%.cpp $(LIBI2PD)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-gost: test-gost.cpp $(LIBI2PD)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-gost-sig: test-gost-sig.cpp $(LIBI2PD)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-aeadchacha20poly1305: test-aeadchacha20poly1305.cpp $(LIBI2PD)
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-blinding: test-blinding.cpp $(LIBI2PD)
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-elligator: test-elligator.cpp $(LIBI2PD)
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-eddsa: test-eddsa.cpp $(LIBI2PD)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-aes: test-aes.cpp $(LIBI2PD)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-address-mapper: test-address-mapper.cpp $(LIBI2PD) $(LIBI2PD_CLIENT)
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) $(LDFLAGS) -o $@ test-address-mapper.cpp -Wl,--start-group $(LIBI2PD_CLIENT) $(LIBI2PD) -Wl,--end-group -lboost_program_options -lssl -lcrypto -lz -lpthread -latomic

run: $(TESTS)
	@for TEST in $(TESTS); do echo Running $$TEST; ./$$TEST ; done

clean:
	rm -f $(TESTS)
