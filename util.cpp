#include "util.h"

namespace i2p
{
namespace util
{
std::map<std::string, std::string> mapArgs;

void ParseArguments(int argc, const char* const argv[])
{
	mapArgs.clear();
    for (int i = 1; i < argc; i++)
    {
    	std::string strKey (argv[i]);
    	std::string strValue;
    	size_t has_data = strKey.find('=');
    	if (has_data != std::string::npos)
    	{
    		strValue = strKey.substr(has_data+1);
    		strKey = strKey.substr(0, has_data);
    	}
    	if (strKey[0] != '-')
    		break;

        mapArgs[strKey] = strValue;
    }
}

int GetIntArg(const std::string& strArg, int nDefault)
{
    if (mapArgs.count(strArg))
        return atoi(mapArgs[strArg].c_str());
    return nDefault;
}

std::string GetStringArg(const std::string& strArg, std::string nDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return nDefault;
}


} // Namespace end
}
