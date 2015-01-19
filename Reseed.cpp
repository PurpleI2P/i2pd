#include <string.h>
#include <fstream>
#include <sstream>
#include <boost/regex.hpp>
#include <boost/filesystem.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/crc.h>
#include <cryptopp/zinflate.h>
#include "I2PEndian.h"
#include "Reseed.h"
#include "Log.h"
#include "Identity.h"
#include "CryptoConst.h"
#include "NetDb.h"
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

	int Reseeder::ReseedNowSU3 ()
	{
		CryptoPP::AutoSeededRandomPool rnd;
		auto ind = rnd.GenerateWord32 (0, httpReseedHostList.size() - 1);
		std::string reseedHost = httpReseedHostList[ind];
		return ReseedFromSU3 (reseedHost);
	}

	int Reseeder::ReseedFromSU3 (const std::string& host)
	{
		std::string url = host + "i2pseeds.su3";
		LogPrint (eLogInfo, "Dowloading SU3 from ", host);
		std::string su3 = i2p::util::http::httpRequest (url);
		if (su3.length () > 0)
		{
			std::stringstream s(su3);
			return ProcessSU3Stream (s);
		}
		else
		{
			LogPrint (eLogWarning, "SU3 download failed");
			return 0;
		}
	}
	
	int Reseeder::ProcessSU3File (const char * filename)
	{
		std::ifstream s(filename, std::ifstream::binary);
		if (s.is_open ())	
			return ProcessSU3Stream (s);
		else
		{
			LogPrint (eLogError, "Can't open file ", filename);
			return 0;
		}
	}

	const char SU3_MAGIC_NUMBER[]="I2Psu3";	
	const uint32_t ZIP_HEADER_SIGNATURE = 0x04034B50;
	const uint32_t ZIP_CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;	
	const uint16_t ZIP_BIT_FLAG_DATA_DESCRIPTOR = 0x0008;	
	int Reseeder::ProcessSU3Stream (std::istream& s)
	{
		char magicNumber[7];
		s.read (magicNumber, 7); // magic number and zero byte 6
		if (strcmp (magicNumber, SU3_MAGIC_NUMBER))
		{
			LogPrint (eLogError, "Unexpected SU3 magic number");	
			return 0;
		}			
		s.seekg (1, std::ios::cur); // su3 file format version
		SigningKeyType signatureType;
		s.read ((char *)&signatureType, 2);  // signature type
		signatureType = be16toh (signatureType);
		uint16_t signatureLength;
		s.read ((char *)&signatureLength, 2);  // signature length
		signatureLength = be16toh (signatureLength);
		s.seekg (1, std::ios::cur); // unused
		uint8_t versionLength;
		s.read ((char *)&versionLength, 1);  // version length	
		s.seekg (1, std::ios::cur); // unused
		uint8_t signerIDLength;
		s.read ((char *)&signerIDLength, 1);  // signer ID length	
		uint64_t contentLength;
		s.read ((char *)&contentLength, 8);  // content length	
		contentLength = be64toh (contentLength);
		s.seekg (1, std::ios::cur); // unused
		uint8_t fileType;
		s.read ((char *)&fileType, 1);  // file type	
		if (fileType != 0x00) //  zip file
		{
			LogPrint (eLogError, "Can't handle file type ", (int)fileType);	
			return 0;
		}
		s.seekg (1, std::ios::cur); // unused
		uint8_t contentType;
		s.read ((char *)&contentType, 1);  // content type	
		if (contentType != 0x03) // reseed data
		{
			LogPrint (eLogError, "Unexpected content type ", (int)contentType);	
			return 0;
		}
		s.seekg (12, std::ios::cur); // unused

		s.seekg (versionLength, std::ios::cur); // skip version
		char signerID[256];
		s.read (signerID, signerIDLength); // signerID
		signerID[signerIDLength] = 0;
		
		//try to verify signature
		auto it = m_SigningKeys.find (signerID);
		if (it != m_SigningKeys.end ())
		{
			// TODO: implement all signature types
			if (signatureType == SIGNING_KEY_TYPE_RSA_SHA512_4096)
			{
				size_t pos = s.tellg ();
				size_t tbsLen = pos + contentLength;
				uint8_t * tbs = new uint8_t[tbsLen];
				s.seekg (0, std::ios::beg);
				s.read ((char *)tbs, tbsLen);
				uint8_t * signature = new uint8_t[signatureLength];
				s.read ((char *)signature, signatureLength);
				// RSA-raw
				i2p::crypto::RSASHA5124096RawVerifier verifier(it->second);
				verifier.Update (tbs, tbsLen);
				if (!verifier.Verify (signature))
					LogPrint (eLogWarning, "SU3 signature verification failed");
				delete[] signature;
				delete[] tbs;
				s.seekg (pos, std::ios::beg);
			}
			else
				LogPrint (eLogWarning, "Signature type ", signatureType, " is not supported");
		}
		else
			LogPrint (eLogWarning, "Certificate for ", signerID, " not loaded");
		
		// handle content
		int numFiles = 0;
		size_t contentPos = s.tellg ();
		while (!s.eof ())
		{	
			uint32_t signature;
			s.read ((char *)&signature, 4);
			signature = le32toh (signature);
			if (signature == ZIP_HEADER_SIGNATURE)
			{
				// next local file
				s.seekg (2, std::ios::cur); // version
				uint16_t bitFlag;
				s.read ((char *)&bitFlag, 2);	
				bitFlag = le16toh (bitFlag);
				uint16_t compressionMethod;
				s.read ((char *)&compressionMethod, 2);	
				compressionMethod = le16toh (compressionMethod);
				s.seekg (4, std::ios::cur); // skip fields we don't care about
				uint32_t compressedSize, uncompressedSize; 
				uint8_t crc32[4];
				s.read ((char *)crc32, 4);	
				s.read ((char *)&compressedSize, 4);	
				compressedSize = le32toh (compressedSize);	
				s.read ((char *)&uncompressedSize, 4);
				uncompressedSize = le32toh (uncompressedSize);	
				uint16_t fileNameLength, extraFieldLength; 
				s.read ((char *)&fileNameLength, 2);	
				fileNameLength = le16toh (fileNameLength);
				s.read ((char *)&extraFieldLength, 2);
				extraFieldLength = le16toh (extraFieldLength);
				char localFileName[255];
				s.read (localFileName, fileNameLength);
				localFileName[fileNameLength] = 0;
				s.seekg (extraFieldLength, std::ios::cur);
				// take care about data desriptor if presented
				if (bitFlag & ZIP_BIT_FLAG_DATA_DESCRIPTOR)
				{
					size_t pos = s.tellg ();
					if (!FindZipDataDescriptor (s))
					{
						LogPrint (eLogError, "SU3 archive data descriptor not found");
						return numFiles;
					}								
	
					s.read ((char *)crc32, 4);	
					s.read ((char *)&compressedSize, 4);	
					compressedSize = le32toh (compressedSize) + 4; // ??? we must consider signature as part of compressed data
					s.read ((char *)&uncompressedSize, 4);
					uncompressedSize = le32toh (uncompressedSize);	

					// now we know compressed and uncompressed size
					s.seekg (pos, std::ios::beg); // back to compressed data
				}

				LogPrint (eLogDebug, "Proccessing file ", localFileName, " ", compressedSize, " bytes");
				if (!compressedSize)
				{
					LogPrint (eLogWarning, "Unexpected size 0. Skipped");
					continue;
				}	
				
				uint8_t * compressed = new uint8_t[compressedSize];
				s.read ((char *)compressed, compressedSize);
				if (compressionMethod) // we assume Deflate
				{
					CryptoPP::Inflator decompressor;
					decompressor.Put (compressed, compressedSize);	
					decompressor.MessageEnd();
					if (decompressor.MaxRetrievable () <= uncompressedSize)
					{
						uint8_t * uncompressed = new uint8_t[uncompressedSize];	
						decompressor.Get (uncompressed, uncompressedSize);	
						if (CryptoPP::CRC32().VerifyDigest (crc32, uncompressed, uncompressedSize))
						{
							i2p::data::netdb.AddRouterInfo (uncompressed, uncompressedSize);
							numFiles++;
						}
						else
							LogPrint (eLogError, "CRC32 verification failed");
						delete[] uncompressed;
					}
					else
						LogPrint (eLogError, "Actual uncompressed size ", decompressor.MaxRetrievable (), " exceed ", uncompressedSize, " from header");
				}	
				else // no compression
				{
					i2p::data::netdb.AddRouterInfo (compressed, compressedSize);
					numFiles++;
				}	
				delete[] compressed;
				if (bitFlag & ZIP_BIT_FLAG_DATA_DESCRIPTOR)
					s.seekg (12, std::ios::cur); // skip data descriptor section if presented (12 = 16 - 4)
			}
			else
			{
				if (signature != ZIP_CENTRAL_DIRECTORY_HEADER_SIGNATURE)
					LogPrint (eLogWarning, "Missing zip central directory header");
				break; // no more files
			}
			size_t end = s.tellg ();
			if (end - contentPos >= contentLength)
				break; // we are beyond contentLength
		}
		return numFiles;
	}

	const uint8_t ZIP_DATA_DESCRIPTOR_SIGNATURE[] = { 0x50, 0x4B, 0x07, 0x08 };	
	bool Reseeder::FindZipDataDescriptor (std::istream& s)
	{
		size_t nextInd = 0;	
		while (!s.eof ())
		{
			uint8_t nextByte;
			s.read ((char *)&nextByte, 1);
			if (nextByte == ZIP_DATA_DESCRIPTOR_SIGNATURE[nextInd])	
			{
				nextInd++;
				if (nextInd >= sizeof (ZIP_DATA_DESCRIPTOR_SIGNATURE))
					return true;
			}
			else
				nextInd = 0;
		}
		return false;
	}

	const char CERTIFICATE_HEADER[] = "-----BEGIN CERTIFICATE-----";
	const char CERTIFICATE_FOOTER[] = "-----END CERTIFICATE-----";
	void Reseeder::LoadCertificate (const std::string& filename)
	{
		std::ifstream s(filename, std::ifstream::binary);
		if (s.is_open ())	
		{
			s.seekg (0, std::ios::end);
			size_t len = s.tellg ();
			s.seekg (0, std::ios::beg);
			char buf[2048];
			s.read (buf, len);
			std::string cert (buf, len);
			// assume file in pem format
			auto pos1 = cert.find (CERTIFICATE_HEADER);	
			auto pos2 = cert.find (CERTIFICATE_FOOTER);	
			if (pos1 == std::string::npos || pos2 == std::string::npos)
			{
				LogPrint (eLogError, "Malformed certificate file");
				return;
			}	
			pos1 += strlen (CERTIFICATE_HEADER);
			pos2 -= pos1;
			std::string base64 = cert.substr (pos1, pos2);

			CryptoPP::ByteQueue queue;
			CryptoPP::Base64Decoder decoder; // regular base64 rather than I2P 
			decoder.Attach (new CryptoPP::Redirector (queue));
			decoder.Put ((const uint8_t *)base64.data(), base64.length());
			decoder.MessageEnd ();

			// extract X.509
			CryptoPP::BERSequenceDecoder x509Cert (queue);
			CryptoPP::BERSequenceDecoder tbsCert (x509Cert);
			// version
			uint32_t ver;
			CryptoPP::BERGeneralDecoder context (tbsCert, CryptoPP::CONTEXT_SPECIFIC | CryptoPP::CONSTRUCTED);
			CryptoPP::BERDecodeUnsigned<uint32_t>(context, ver, CryptoPP::INTEGER);
			// serial
			CryptoPP::Integer serial;
       		serial.BERDecode(tbsCert);	
			// signature
			CryptoPP::BERSequenceDecoder signature (tbsCert);
       		signature.SkipAll();
			
			// issuer
			std::string name;
			CryptoPP::BERSequenceDecoder issuer (tbsCert);
			{
				CryptoPP::BERSetDecoder c (issuer);	c.SkipAll();
				CryptoPP::BERSetDecoder st (issuer); st.SkipAll();
				CryptoPP::BERSetDecoder l (issuer); l.SkipAll();
				CryptoPP::BERSetDecoder o (issuer); o.SkipAll();
				CryptoPP::BERSetDecoder ou (issuer); ou.SkipAll();
				CryptoPP::BERSetDecoder cn (issuer);
				{		
					CryptoPP::BERSequenceDecoder attributes (cn);
					{			
						CryptoPP::BERGeneralDecoder ident(attributes, CryptoPP::OBJECT_IDENTIFIER);
						ident.SkipAll ();
						CryptoPP::BERDecodeTextString (attributes, name, CryptoPP::UTF8_STRING);
					}	
				}	
			}	
       		issuer.SkipAll();
			// validity
			CryptoPP::BERSequenceDecoder validity (tbsCert);
       		validity.SkipAll();
			// subject
			CryptoPP::BERSequenceDecoder subject (tbsCert);
       		subject.SkipAll();
			// public key
			CryptoPP::BERSequenceDecoder publicKey (tbsCert);
			{			
				CryptoPP::BERSequenceDecoder ident (publicKey);
				ident.SkipAll ();
				CryptoPP::BERGeneralDecoder key (publicKey, CryptoPP::BIT_STRING);
				key.Skip (1); // FIXME: probably bug in crypto++
				CryptoPP::BERSequenceDecoder keyPair (key);
				CryptoPP::Integer n;
       			n.BERDecode (keyPair);
				if (name.length () > 0) 
				{	
					PublicKey value;
					n.Encode (value, 512);
					m_SigningKeys[name] = value;
				}		
				else
					LogPrint (eLogWarning, "Unknown issuer. Skipped");
			}	
       		publicKey.SkipAll();
			
			tbsCert.SkipAll();
			x509Cert.SkipAll();
		}
		else
			LogPrint (eLogError, "Can't open certificate file ", filename);
	}

	void Reseeder::LoadCertificates ()
	{
		boost::filesystem::path reseedDir = i2p::util::filesystem::GetCertificatesDir() / "reseed";
		
		if (!boost::filesystem::exists (reseedDir))
		{
			LogPrint (eLogWarning, "Reseed certificates not loaded. ", reseedDir, " doesn't exist");
			return;
		}

		int numCertificates = 0;
		boost::filesystem::directory_iterator end; // empty
		for (boost::filesystem::directory_iterator it (reseedDir); it != end; ++it)
		{
			if (boost::filesystem::is_regular_file (it->status()) && it->path ().extension () == ".crt")
			{	
				LoadCertificate (it->path ().string ());
				numCertificates++;
			}	
		}	
		LogPrint (eLogInfo, numCertificates, " certificates loaded");
	}	
	
}
}

