#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>

namespace i2p
{
namespace util
{
	extern std::map<std::string, std::string> mapArgs;
	void OptionParser(int argc, const char* const argv[]);
	int GetIntArg(const std::string& strArg, int nDefault);
	const char* GetCharArg(const std::string& strArg, const std::string& nDefault);
	namespace http
	{
		std::string httpRequest(const std::string& address);
		struct url {
    			url(const std::string& url_s); // omitted copy, ==, accessors, ...
			private:
    			void parse(const std::string& url_s);
			public:
    			std::string protocol_, host_, path_, query_;
		};
	}
}
}


#endif
