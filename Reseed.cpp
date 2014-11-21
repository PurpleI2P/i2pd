#include <iostream>
#include <fstream>
#include <boost/regex.hpp>
#include <boost/filesystem.hpp>
#include <cryptopp/gzip.h>
#include "I2PEndian.h"
#include "Reseed.h"
#include "Log.h"
#include "util.h"


namespace i2p
{
namespace data
{

	static std::vector<std::string> httpReseedHostList = {
				"http://193.150.121.66/netDb/",
				"http://netdb.i2p2.no/",
				"http://reseed.i2p-projekt.de/",
				"http://cowpuncher.drollette.com/netdb/",
				"http://i2p.mooo.com/netDb/",
				"http://reseed.info/",
				"http://uk.reseed.i2p2.no/",
				"http://us.reseed.i2p2.no/",
				"http://jp.reseed.i2p2.no/",
				"http://i2p-netdb.innovatio.no/",
				"http://ieb9oopo.mooo.com"
			};

	//TODO: Remember to add custom port support. Not all serves on 443
	static std::vector<std::string> httpsReseedHostList = {
				"https://193.150.121.66/netDb/",
				"https://netdb.i2p2.no/",
				"https://reseed.i2p-projekt.de/",
				"https://cowpuncher.drollette.com/netdb/",
				"https://i2p.mooo.com/netDb/",
				"https://reseed.info/",
				"https://i2p-netdb.innovatio.no/",
				"https://ieb9oopo.mooo.com/",
				"https://ssl.webpack.de/ivae2he9.sg4.e-plaza.de/" // Only HTTPS and SU3 (v2) support
			};
	
	//TODO: Implement v2 reseeding. Lightweight zip library is needed.
	//TODO: Implement SU3, utils.
	Reseeder::Reseeder()
	{
	}

	Reseeder::~Reseeder()
	{
	}

	bool Reseeder::reseedNow()
	{
		try
		{
			// Seems like the best place to try to intercept with SSL
			/*ssl_server = true;
			try {
				// SSL
			}
			catch (std::exception& e)
			{
				LogPrint("Exception in SSL: ", e.what());
			}*/
			std::string reseedHost = httpReseedHostList[(rand() % httpReseedHostList.size())];
			LogPrint("Reseeding from ", reseedHost);
			std::string content = i2p::util::http::httpRequest(reseedHost);
			if (content == "")
			{
				LogPrint("Reseed failed");
				return false;
			}
			boost::regex e("<\\s*A\\s+[^>]*href\\s*=\\s*\"([^\"]*)\"", boost::regex::normal | boost::regbase::icase);
			boost::sregex_token_iterator i(content.begin(), content.end(), e, 1);
			boost::sregex_token_iterator j;
			//TODO: Ugly code, try to clean up.
			//TODO: Try to reduce N number of variables
			std::string name;
			std::string routerInfo;
			std::string tmpUrl;
			std::string filename;
			std::string ignoreFileSuffix = ".su3";
			boost::filesystem::path root = i2p::util::filesystem::GetDataDir();
			while (i != j)
			{
				name = *i++;
				if (name.find(ignoreFileSuffix)!=std::string::npos)
					continue;
				LogPrint("Downloading ", name);
				tmpUrl = reseedHost;
				tmpUrl.append(name);
				routerInfo = i2p::util::http::httpRequest(tmpUrl);
				if (routerInfo.size()==0)
					continue;
				filename = root.string();
#ifndef _WIN32
				filename += "/netDb/r";
#else
				filename += "\\netDb\\r";
#endif
				filename += name.at(11); // first char in id
#ifndef _WIN32
				filename.append("/");
#else
				filename.append("\\");
#endif
				filename.append(name.c_str());
				std::ofstream outfile (filename, std::ios::binary);
				outfile << routerInfo;
				outfile.close();
			}
			return true;
		}
		catch (std::exception& ex)
		{
			//TODO: error reporting
			return false;
		}
		return false;
	}	

	void ProcessSU3File (const char * filename)
	{
		static uint32_t headerSignature = htole32 (0x04044B50);

		std::ifstream s(filename, std::ifstream::binary);
		if (s.is_open ())	
		{	
			while (!s.eof ())
			{
				uint32_t signature;
				s.read ((char *)&signature, 4);
				if (signature == headerSignature)
				{
					// next local file
					s.seekg (14, std::ios::cur); // skip field we don't care about
					uint32_t compressedSize, uncompressedSize; 
					s.read ((char *)&compressedSize, 4);	
					compressedSize = le32toh (compressedSize);	
					s.read ((char *)&uncompressedSize, 4);
					uncompressedSize = le32toh (uncompressedSize);	
					uint16_t fileNameLength, extraFieldLength; 
					s.read ((char *)&fileNameLength, 2);	
					fileNameLength = le32toh (fileNameLength);
					s.read ((char *)&extraFieldLength, 2);
					extraFieldLength = le32toh (extraFieldLength);
					char localFileName[255];
					s.read (localFileName, fileNameLength);
					localFileName[fileNameLength] = 0;
					s.seekg (extraFieldLength, std::ios::cur);

					uint8_t * compressed = new uint8_t[compressedSize];
					s.read ((char *)compressed, compressedSize);
					CryptoPP::Gunzip decompressor;
					decompressor.Put (compressed, compressedSize);
					delete[] compressed;	
					if (decompressor.MaxRetrievable () <= uncompressedSize)
					{
						uint8_t * uncompressed = new uint8_t[uncompressedSize];	
						decompressor.Get (uncompressed, decompressor.MaxRetrievable ());	
						// TODO: save file		
						delete[] uncompressed;
					}
					else
						LogPrint (eLogError, "Actual uncompressed size ", decompressor.MaxRetrievable (), " exceed ", uncompressedSize, " from header");
				}
				else
					break; // no more files
			}
		}
		else
			LogPrint (eLogError, "Can't open file ", filename);
	}

}
}

