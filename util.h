#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>

namespace i2p
{
namespace util
{
	extern std::map<std::string, std::string> mapArgs;
	void ParseArguments(int argc, const char* const argv[]);
	int GetIntArg(const std::string& strArg, int nDefault);

}
}


#endif
