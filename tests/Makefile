CXXFLAGS += -Wall -Wno-unused-parameter -Wextra -pedantic -O0 -g -std=c++11 -D_GLIBCXX_USE_NANOSLEEP=1 -DOPENSSL_SUPPRESS_DEPRECATED -pthread -Wl,--unresolved-symbols=ignore-in-object-files
INCFLAGS += -I../libi2pd

TESTS = test-gost test-gost-sig test-base-64 test-x25519 test-aeadchacha20poly1305 test-blinding test-elligator \
        test-http-merge_chunked test-http-res test-http-url_decode test-http-req test-http-url

LDLIBS = \
    -lboost_system \
    -lboost_filesystem \
    -lboost_system \
    -lcrypto \
    -lssl \
    -L.. \
    -li2pd

all: $(TESTS) run

test-http-%: test-http-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-base-%: test-base-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-gost: test-gost.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-gost-sig: test-gost-sig.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-x25519: test-x25519.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-aeadchacha20poly1305: test-aeadchacha20poly1305.cpp
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-blinding: test-blinding.cpp
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

test-elligator: test-elligator.cpp
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ $(LDLIBS)

run: $(TESTS)
	@for TEST in $(TESTS); do ./$$TEST ; done

clean:
	rm -f $(TESTS)
