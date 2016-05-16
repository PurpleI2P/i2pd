CXXFLAGS += -Wall -Wextra -pedantic -O0 -g -std=c++11 -D_GLIBCXX_USE_NANOSLEEP=1

TESTS = test-http-url test-http-req test-http-res test-http-url_decode

all: $(TESTS) run

test-http-%: test-http-%.cpp ../HTTP.cpp
	$(CXX) $(CXXFLAGS) $(NEEDED_CXXFLAGS) $(INCFLAGS) -o $@ $^

run: $(TESTS)
	@for TEST in $(TESTS); do ./$$TEST ; done

clean:
	rm -f $(TESTS)
