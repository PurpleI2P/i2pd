#include <string.h>
#include <fstream>
#include <sstream>
#include <boost/regex.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/crc.h>
#include <cryptopp/hmac.h>
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
				// "http://193.150.121.66/netDb/",  // unstable
				// "http://us.reseed.i2p2.no/",     // misconfigured, not serving reseed data
				// "http://jp.reseed.i2p2.no/",     // Really outdated RIs
				"http://netdb.i2p2.no/",            // only SU3 (v2) support
				"http://i2p.mooo.com/netDb/",
				"http://uk.reseed.i2p2.no/",
				"http://i2p-netdb.innovatio.no/"
			};

	//TODO: Remember to add custom port support. Not all serves on 443
	static std::vector<std::string> httpsReseedHostList = {
				// "https://193.150.121.66/netDb/",  // unstable
				// "https://i2p-netdb.innovatio.no/",// Vuln to POODLE
				"https://netdb.i2p2.no/",            // Only SU3 (v2) support
				"https://reseed.i2p-projekt.de/",    // Only HTTPS
				"https://cowpuncher.drollette.com/netdb/",  // Only HTTPS and SU3 (v2) support -- will move to a new location
				// following hosts are fine but don't support AES256 
				/*"https://i2p.mooo.com/netDb/",
				"https://link.mx24.eu/",             // Only HTTPS and SU3 (v2) support
				"https://i2pseed.zarrenspry.info/",  // Only HTTPS and SU3 (v2) support
				"https://ieb9oopo.mooo.com/"         // Only HTTPS and SU3 (v2) support*/
			};
	
	Reseeder::Reseeder()
	{
	}

	Reseeder::~Reseeder()
	{
	}

	bool Reseeder::reseedNow()
	{
		// This method is deprecated
		try
		{
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
		auto ind = rnd.GenerateWord32 (0, httpReseedHostList.size() - 1 +  httpsReseedHostList.size () - 1);
		std::string reseedHost = (ind < httpReseedHostList.size()) ? httpReseedHostList[ind] : 
			httpsReseedHostList[ind - httpReseedHostList.size()]; 
		return ReseedFromSU3 (reseedHost, ind >= httpReseedHostList.size());
	}

	int Reseeder::ReseedFromSU3 (const std::string& host, bool https)
	{
		std::string url = host + "i2pseeds.su3";
		LogPrint (eLogInfo, "Dowloading SU3 from ", host);
		std::string su3 = https ? HttpsRequest (url) : i2p::util::http::httpRequest (url);
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
			
			LoadCertificate (queue);
		}
		else
			LogPrint (eLogError, "Can't open certificate file ", filename);
	}

	std::string Reseeder::LoadCertificate (CryptoPP::ByteQueue& queue)
	{
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
		return name;
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

	std::string Reseeder::HttpsRequest (const std::string& address)
	{
		i2p::util::http::url u(address);
		TlsSession session (u.host_, 443);
		
		// send request		
		std::stringstream ss;
		ss << "GET " << u.path_ << " HTTP/1.1\r\nHost: " << u.host_
		<< "\r\nAccept: */*\r\n" << "User-Agent: Wget/1.11.4\r\n" << "Connection: close\r\n\r\n";	
		session.Send ((uint8_t *)ss.str ().c_str (), ss.str ().length ());

		// read response
		std::stringstream rs;
		while (session.Receive (rs))
			;
		return i2p::util::http::GetHttpContent (rs);
	}	

	TlsSession::TlsSession (const std::string& host, int port):
		m_Seqn (0)
	{
		m_Site.connect(host, boost::lexical_cast<std::string>(port));
		if (m_Site.good ())
		{
			Handshake ();
		}
		else
			LogPrint (eLogError, "Can't connect to ", host, ":", port);
	}	
	
	void TlsSession::Handshake ()
	{
		static uint8_t clientHello[] = 
		{
			0x16, // handshake
			0x03, 0x03, // version (TLS 1.2)
			0x00, 0x2F, // length of handshake
			// handshake
			0x01, // handshake type (client hello)
			0x00, 0x00, 0x2B, // length of handshake payload 
			// client hello
			0x03, 0x03, // highest version supported (TLS 1.2)
			0x45, 0xFA, 0x01, 0x19, 0x74, 0x55, 0x18, 0x36, 
			0x42, 0x05, 0xC1, 0xDD, 0x4A, 0x21, 0x80, 0x80, 
			0xEC, 0x37, 0x11, 0x93, 0x16, 0xF4, 0x66, 0x00, 
			0x12, 0x67, 0xAB, 0xBA, 0xFF, 0x29, 0x13, 0x9E, // 32 random bytes
			0x00, // session id length
			0x00, 0x02, // chiper suites length
			0x00, 0x3D, // RSA_WITH_AES_256_CBC_SHA256
			0x01, // compression methods length
			0x00,  // no compression
			0x00, 0x00 // extensions length
		};	

		static uint8_t changeCipherSpecs[] =
		{
			0x14, // change cipher specs
			0x03, 0x03, // version (TLS 1.2)
			0x00, 0x01, // length
			0x01 // type
		};

		static uint8_t finished[] =
		{
			0x16, // handshake
			0x03, 0x03, // version (TLS 1.2)
			0x00, 0x50, // length of handshake (80 bytes)
			// handshake (encrypted)
			// unencrypted context
			//  0x14 handshake type (finished)
			// 0x00, 0x00, 0x0C  length of handshake payload 
			// 12 bytes of verified data
		};
	
		// send ClientHello
		m_Site.write ((char *)clientHello, sizeof (clientHello));
		m_FinishedHash.Update (clientHello + 5, sizeof (clientHello) - 5);
		// read ServerHello
		uint8_t type;
		m_Site.read ((char *)&type, 1); 
		uint16_t version;
		m_Site.read ((char *)&version, 2); 
		uint16_t length;
		m_Site.read ((char *)&length, 2); 
		length = be16toh (length);
		char * serverHello = new char[length];
		m_Site.read (serverHello, length);
		m_FinishedHash.Update ((uint8_t *)serverHello, length);
		uint8_t serverRandom[32];
		if (serverHello[0] == 0x02) // handshake type server hello
			memcpy (serverRandom, serverHello + 6, 32);
		else
			LogPrint (eLogError, "Unexpected handshake type ", (int)serverHello[0]);
		delete[] serverHello;
		// read Certificate
		m_Site.read ((char *)&type, 1); 
		m_Site.read ((char *)&version, 2); 
		m_Site.read ((char *)&length, 2); 
		length = be16toh (length);
		char * certificate = new char[length];
		m_Site.read (certificate, length);
		m_FinishedHash.Update ((uint8_t *)certificate, length);
		CryptoPP::RSA::PublicKey publicKey;
		// 0 - handshake type
		// 1 - 3 - handshake payload length
		// 4 - 6 - length of array of certificates
		// 7 - 9 - length of certificate
		if (certificate[0] == 0x0B) // handshake type certificate
			publicKey = ExtractPublicKey ((uint8_t *)certificate + 10, length - 10);
		else
			LogPrint (eLogError, "Unexpected handshake type ", (int)certificate[0]);
		delete[] certificate;
		// read ServerHelloDone
		m_Site.read ((char *)&type, 1); 
		m_Site.read ((char *)&version, 2); 
		m_Site.read ((char *)&length, 2); 
		length = be16toh (length);
		char * serverHelloDone = new char[length];
		m_Site.read (serverHelloDone, length);
		m_FinishedHash.Update ((uint8_t *)serverHelloDone, length);
		if (serverHelloDone[0] != 0x0E) // handshake type hello done
			LogPrint (eLogError, "Unexpected handshake type ", (int)serverHelloDone[0]);
		delete[] serverHelloDone;
		// our turn now
		// generate secret key
		uint8_t secret[48]; 
		secret[0] = 3; secret[1] = 3; // version
		m_Rnd.GenerateBlock (secret + 2, 46); // 46 random bytes
		// encrypt RSA
 		CryptoPP::RSAES_PKCS1v15_Encryptor encryptor(publicKey);
		size_t encryptedLen = encryptor.CiphertextLength (48); // number of bytes for encrypted 48 bytes, usually 256 (2048 bits key)
		uint8_t * encrypted = new uint8_t[encryptedLen + 2]; // + 2 bytes for length
		htobe16buf (encrypted, encryptedLen); // first two bytes means length 
		encryptor.Encrypt (m_Rnd, secret, 48, encrypted + 2);
		// send ClientKeyExchange
		// 0x10 - handshake type "client key exchange"
		SendHandshakeMsg (0x10, encrypted, encryptedLen + 2);
		delete[] encrypted;
		// send ChangeCipherSpecs
		m_Site.write ((char *)changeCipherSpecs, sizeof (changeCipherSpecs));
		// calculate master secret
		uint8_t masterSecret[48], random[64];
		memcpy (random, clientHello + 11, 32);
		memcpy (random + 32, serverRandom, 32);
		PRF (secret, "master secret", random, 64, 48, masterSecret);
		// expand master secret			
		uint8_t keys[128]; // clientMACKey(32), serverMACKey(32), clientKey(32), serverKey(32)
		memcpy (random, serverRandom, 32);
		memcpy (random + 32, clientHello + 11, 32);
		PRF (masterSecret, "key expansion", random, 64, 128, keys); 
		memcpy (m_MacKey, keys, 32);
		m_Encryption.SetKey (keys + 64);
		m_Decryption.SetKey (keys + 96);

		// send finished
		uint8_t finishedHashDigest[32], finishedPayload[40], encryptedPayload[80];
		finishedPayload[0] = 0x14; // handshake type (finished)
		finishedPayload[1] = 0; finishedPayload[2] = 0; finishedPayload[3] = 0x0C; // 12 bytes
		m_FinishedHash.Final (finishedHashDigest);
		PRF (masterSecret, "client finished", finishedHashDigest, 32, 12, finishedPayload + 4);
		uint8_t mac[32];
		CalculateMAC (0x16, finishedPayload, 16, mac);
		Encrypt (finishedPayload, 16, mac, encryptedPayload);
		m_Site.write ((char *)finished, sizeof (finished));
		m_Site.write ((char *)encryptedPayload, 80);
		// read ChangeCipherSpecs
		uint8_t changeCipherSpecs1[6];
		m_Site.read ((char *)changeCipherSpecs1, 6);
		// read finished
		m_Site.read ((char *)&type, 1); 
		m_Site.read ((char *)&version, 2); 
		m_Site.read ((char *)&length, 2); 
		length = be16toh (length);
		char * finished1 = new char[length];
		m_Site.read (finished1, length);
		delete[] finished1;
	}

	void TlsSession::SendHandshakeMsg (uint8_t handshakeType, uint8_t * data, size_t len)
	{
		uint8_t handshakeHeader[9];
		handshakeHeader[0] = 0x16; // handshake
 		handshakeHeader[1] = 0x03; handshakeHeader[2] = 0x03; // version is always TLS 1.2 (3,3) 
		htobe16buf (handshakeHeader + 3, len + 4); // length of payload
		//payload starts
		handshakeHeader[5] = handshakeType; // handshake type
		handshakeHeader[6] = 0; // highest byte of payload length is always zero
		htobe16buf (handshakeHeader + 7, len); // length of data
		m_Site.write ((char *)handshakeHeader, 9);
		m_FinishedHash.Update (handshakeHeader + 5, 4); // only payload counts
		m_Site.write ((char *)data, len);
		m_FinishedHash.Update (data, len);
	}

	void TlsSession::PRF (const uint8_t * secret, const char * label, const uint8_t * random, size_t randomLen,
		size_t len, uint8_t * buf)
	{
		// secret is assumed 48 bytes	
		// random is not more than 64 bytes
 		CryptoPP::HMAC<CryptoPP::SHA256> hmac (secret, 48);	
		uint8_t seed[96]; size_t seedLen;
		seedLen = strlen (label);	
		memcpy (seed, label, seedLen);
		memcpy (seed + seedLen, random, randomLen);
		seedLen += randomLen;

		size_t offset = 0;
		uint8_t a[128];
		hmac.CalculateDigest (a, seed, seedLen);
		while (offset < len)
		{
			memcpy (a + 32, seed, seedLen);
			hmac.CalculateDigest (buf + offset, a, seedLen + 32);
			offset += 32;
			hmac.CalculateDigest (a, a, 32);
		}
	}

	size_t TlsSession::Encrypt (const uint8_t * in, size_t len, const uint8_t * mac, uint8_t * out)
	{
		size_t size = 0;
		m_Rnd.GenerateBlock (out, 16); // iv
		size += 16;
		m_Encryption.SetIV (out);
		memcpy (out + size, in, len);
		size += len;
		memcpy (out + size, mac, 32);
		size += 32;	
		uint8_t paddingSize = len + 1;
		paddingSize &= 0x0F;  // %16
		if (paddingSize > 0) paddingSize = 16 - paddingSize;
		memset (out + size, paddingSize, paddingSize + 1); // paddind and last byte are equal to padding size
		size += paddingSize + 1;
		m_Encryption.Encrypt (out + 16, size - 16, out + 16);
		return size;	
	}

	size_t TlsSession::Decrypt (uint8_t * buf, size_t len)
	{
		m_Decryption.SetIV (buf);
		m_Decryption.Decrypt (buf + 16, len - 16, buf + 16);
		return len - 48 - buf[len -1] - 1; // IV(16), mac(32) and padding
	}

	void TlsSession::CalculateMAC (uint8_t type, const uint8_t * buf, size_t len, uint8_t * mac)
	{
		uint8_t header[13]; // seqn (8) + type (1) + version (2) + length (2)
		htobe64buf (header, m_Seqn);
		header[8] = type; header[9] = 3; header[10] = 3; // 3,3 means TLS 1.2 
		htobe16buf (header + 11, len);
		CryptoPP::HMAC<CryptoPP::SHA256> hmac (m_MacKey, 32);	
		hmac.Update (header, 13);
		hmac.Update (buf, len);
		hmac.Final (mac);	
		m_Seqn++;
	}

	CryptoPP::RSA::PublicKey TlsSession::ExtractPublicKey (const uint8_t * certificate, size_t len)
	{
		CryptoPP::ByteQueue queue;
		queue.Put (certificate, len);	
		queue.MessageEnd ();
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
		CryptoPP::BERSequenceDecoder issuer (tbsCert);
   		issuer.SkipAll();
		// validity
		CryptoPP::BERSequenceDecoder validity (tbsCert);
   		validity.SkipAll();
		// subject
		CryptoPP::BERSequenceDecoder subject (tbsCert);
   		subject.SkipAll();
		// public key
		CryptoPP::BERSequenceDecoder publicKey (tbsCert);			
		CryptoPP::BERSequenceDecoder ident (publicKey);
		ident.SkipAll ();
		CryptoPP::BERGeneralDecoder key (publicKey, CryptoPP::BIT_STRING);
		key.Skip (1); // FIXME: probably bug in crypto++
		CryptoPP::BERSequenceDecoder keyPair (key);
		CryptoPP::Integer n, e;
		n.BERDecode (keyPair);
		e.BERDecode (keyPair);

		CryptoPP::RSA::PublicKey ret; 
		ret.Initialize (n, e);
		return ret;
	}		

	void TlsSession::Send (const uint8_t * buf, size_t len)
	{
		uint8_t * out = new uint8_t[len + 64 + 5]; // 64 = 32 mac + 16 iv + upto 16 padding, 5 = header
		out[0] = 0x17; // application data
		out[1] = 0x03; out[2] = 0x03; // version
		uint8_t mac[32];
		CalculateMAC (0x17, buf, len, mac);
		size_t encryptedLen = Encrypt (buf, len, mac, out + 5);
		htobe16buf (out + 3, encryptedLen);
		m_Site.write ((char *)out, encryptedLen + 5);
		delete[] out;
	}

	bool TlsSession::Receive (std::ostream& rs)
	{
		if (m_Site.eof ()) return false;
		uint8_t type; uint16_t version, length;
		m_Site.read ((char *)&type, 1); 
		m_Site.read ((char *)&version, 2); 
		m_Site.read ((char *)&length, 2); 
		length = be16toh (length);
		uint8_t * buf = new uint8_t[length];
		m_Site.read ((char *)buf, length);
		size_t decryptedLen = Decrypt (buf, length);
		rs.write ((char *)buf + 16, decryptedLen);
		delete[] buf;
		return true;
	}
}
}

