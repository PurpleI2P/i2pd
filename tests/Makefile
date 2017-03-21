CXXFLAGS += -Wall -Wextra -pedantic -O0 -g -std=c++11 -D_GLIBCXX_USE_NANOSLEEP=1

TESTS = test-gost test-gost-sig test-base-64

all: $(TESTS) run

test-http-%: ../HTTP.cpp test-http-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

test-base-%: ../Base.cpp test-base-%.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

test-gost: ../Gost.cpp ../I2PEndian.cpp test-gost.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto

test-gost-sig: ../Gost.cpp ../I2PEndian.cpp ../Signature.cpp ../Crypto.cpp ../Log.cpp test-gost-sig.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^ -lcrypto -lssl -lboost_system

run: $(TESTS)
	@for TEST in $(TESTS); do ./$$TEST ; done

clean:
	rm -f $(TESTS)
