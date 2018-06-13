CXXFLAGS += -Wall -Wextra -pedantic -O0 -g -std=c++11 -D_GLIBCXX_USE_NANOSLEEP=1 -I../libi2pd/ -pthread -Wl,--unresolved-symbols=ignore-in-object-files

TESTS = test-gost test-gost-sig test-base-64 test-x25519 test-aeadchacha20poly1305

all: $(TESTS) run

test-http-%: ../libi2pd/HTTP.cpp test-http-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

test-base-%: ../libi2pd/Base.cpp test-base-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

test-gost: ../libi2pd/Gost.cpp ../libi2pd/I2PEndian.cpp test-gost.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto

test-gost-sig: ../libi2pd/Gost.cpp ../libi2pd/I2PEndian.cpp ../libi2pd/Crypto.cpp ../libi2pd/Log.cpp test-gost-sig.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

test-x25519: ../libi2pd/Ed25519.cpp ../libi2pd/I2PEndian.cpp ../libi2pd/Log.cpp ../libi2pd/Crypto.cpp  test-x25519.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

test-aeadchacha20poly1305: ../libi2pd/Crypto.cpp ../libi2pd/ChaCha20.cpp ../libi2pd/Poly1305.cpp test-aeadchacha20poly1305.cpp
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

run: $(TESTS)
	@for TEST in $(TESTS); do ./$$TEST ; done

clean:
	rm -f $(TESTS)
