CXXFLAGS = -I ../../../
all: keyinfo

keyinfo:
	$(CXX) -o keyinfo keyinfo.cpp $(CXXFLAGS) -std=c++11 ../../../libi2pd.a -lssl -lcrypto -lboost_system

clean:
	$(RM) keyinfo
