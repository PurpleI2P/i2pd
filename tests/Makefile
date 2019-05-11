CXXFLAGS += -Wall -Wextra -pedantic -O0 -g -std=c++11 -D_GLIBCXX_USE_NANOSLEEP=1 -I../libdotnet/ -pthread -Wl,--unresolved-symbols=ignore-in-object-files

TESTS = test-gost test-gost-sig test-base-64 test-x25519 test-aeadchacha20poly1305

all: $(TESTS) run

test-http-%: ../libdotnet/HTTP.cpp test-http-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

test-base-%: ../libdotnet/Base.cpp test-base-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

test-gost: ../libdotnet/Gost.cpp ../libdotnet/DotNetEndian.cpp test-gost.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto

test-gost-sig: ../libdotnet/Gost.cpp ../libdotnet/DotNetEndian.cpp ../libdotnet/Crypto.cpp ../libdotnet/Log.cpp test-gost-sig.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

test-x25519: ../libdotnet/Ed25519.cpp ../libdotnet/DotNetEndian.cpp ../libdotnet/Log.cpp ../libdotnet/Crypto.cpp  test-x25519.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

test-aeadchacha20poly1305: ../libdotnet/Crypto.cpp ../libdotnet/ChaCha20.cpp ../libdotnet/Poly1305.cpp test-aeadchacha20poly1305.cpp
	 $(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

run: $(TESTS)
	@for TEST in $(TESTS); do ./$$TEST ; done

clean:
	rm -f $(TESTS)
