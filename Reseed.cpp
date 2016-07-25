#include <string.h>
#include <fstream>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>

#include "Crypto.h"
#include "I2PEndian.h"
#include "Reseed.h"
#include "FS.h"
#include "Log.h"
#include "Identity.h"
#include "NetDb.h"
#include "HTTP.h"
#include "util.h"

namespace i2p
{
namespace data
{
	static std::vector<std::string> httpsReseedHostList =
	{
#ifdef MESHNET
		// meshnet i2p reseeds
		"https://reseed.i2p.rocks:8443/"
#else
		// mainline i2p reseeds
		"https://reseed.i2p-projekt.de/", // Only HTTPS
				"https://i2p.mooo.com/netDb/",
				"https://netdb.i2p2.no/", // Only SU3 (v3) support, SNI required
		"https://us.reseed.i2p2.no:444/",	
				"https://uk.reseed.i2p2.no:444/",
		"https://i2p.manas.ca:8443/",
		"https://i2p-0.manas.ca:8443/",
				"https://reseed.i2p.vzaws.com:8443/", // Only SU3 (v3) support
				"https://user.mx24.eu/", // Only HTTPS and SU3 (v3) support
				"https://download.xxlspeed.com/" // Only HTTPS and SU3 (v3) support
#endif
	};
 
	Reseeder::Reseeder()
	{
	}

	Reseeder::~Reseeder()
	{
	}

	int Reseeder::ReseedNowSU3 ()
	{
		auto ind = rand () % httpsReseedHostList.size ();
		std::string& reseedHost = httpsReseedHostList[ind];
		return ReseedFromSU3 (reseedHost);
	}

	int Reseeder::ReseedFromSU3 (const std::string& host)
	{
		std::string url = host + "i2pseeds.su3";
		LogPrint (eLogInfo, "Reseed: Downloading SU3 from ", host);
		std::string su3 = HttpsRequest (url);
		if (su3.length () > 0)
		{
			std::stringstream s(su3);
			return ProcessSU3Stream (s);
		}
		else
		{
			LogPrint (eLogWarning, "Reseed: SU3 download failed");
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
			LogPrint (eLogError, "Reseed: Can't open file ", filename);
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
			LogPrint (eLogError, "Reseed: Unexpected SU3 magic number");
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
			LogPrint (eLogError, "Reseed: Can't handle file type ", (int)fileType);
			return 0;
		}
		s.seekg (1, std::ios::cur); // unused
		uint8_t contentType;
		s.read ((char *)&contentType, 1);  // content type	
		if (contentType != 0x03) // reseed data
		{
			LogPrint (eLogError, "Reseed: Unexpected content type ", (int)contentType);
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
				{
					// calculate digest
					uint8_t digest[64];
					SHA512 (tbs, tbsLen, digest);
					// encrypt signature
					BN_CTX * bnctx = BN_CTX_new ();
					BIGNUM * s = BN_new (), * n = BN_new ();
					BN_bin2bn (signature, signatureLength, s);
					BN_bin2bn (it->second, i2p::crypto::RSASHA5124096_KEY_LENGTH, n);
					BN_mod_exp (s, s, i2p::crypto::GetRSAE (), n, bnctx); // s = s^e mod n 
					uint8_t * enSigBuf = new uint8_t[signatureLength];
					i2p::crypto::bn2buf (s, enSigBuf, signatureLength);
					// digest is right aligned
					// we can't use RSA_verify due wrong padding in SU3
					if (memcmp (enSigBuf + (signatureLength - 64), digest, 64))
						LogPrint (eLogWarning, "Reseed: SU3 signature verification failed");
					delete[] enSigBuf;
					BN_free (s); BN_free (n);
					BN_CTX_free (bnctx);
				}	
					
				delete[] signature;
				delete[] tbs;
				s.seekg (pos, std::ios::beg);
			}
			else
				LogPrint (eLogWarning, "Reseed: Signature type ", signatureType, " is not supported");
		}
		else
			LogPrint (eLogWarning, "Reseed: Certificate for ", signerID, " not loaded");
		
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
				uint32_t crc_32;
				s.read ((char *)&crc_32, 4);
				crc_32 = le32toh (crc_32);
				s.read ((char *)&compressedSize, 4);	
				compressedSize = le32toh (compressedSize);	
				s.read ((char *)&uncompressedSize, 4);
				uncompressedSize = le32toh (uncompressedSize);	
				uint16_t fileNameLength, extraFieldLength; 
				s.read ((char *)&fileNameLength, 2);	
				fileNameLength = le16toh (fileNameLength);
				if ( fileNameLength > 255 ) {
					// too big
					LogPrint(eLogError, "Reseed: SU3 fileNameLength too large: ", fileNameLength);
					return numFiles;
				}
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
						LogPrint (eLogError, "Reseed: SU3 archive data descriptor not found");
						return numFiles;
					}									
					s.read ((char *)&crc_32, 4);	
					crc_32 = le32toh (crc_32);
					s.read ((char *)&compressedSize, 4);	
					compressedSize = le32toh (compressedSize) + 4; // ??? we must consider signature as part of compressed data
					s.read ((char *)&uncompressedSize, 4);
					uncompressedSize = le32toh (uncompressedSize);	

					// now we know compressed and uncompressed size
					s.seekg (pos, std::ios::beg); // back to compressed data
				}

				LogPrint (eLogDebug, "Reseed: Proccessing file ", localFileName, " ", compressedSize, " bytes");
				if (!compressedSize)
				{
					LogPrint (eLogWarning, "Reseed: Unexpected size 0. Skipped");
					continue;
				}	
				
				uint8_t * compressed = new uint8_t[compressedSize];
				s.read ((char *)compressed, compressedSize);
				if (compressionMethod) // we assume Deflate
				{
					z_stream inflator;
					memset (&inflator, 0, sizeof (inflator));
					inflateInit2 (&inflator, -MAX_WBITS); // no zlib header
					uint8_t * uncompressed = new uint8_t[uncompressedSize];
					inflator.next_in = compressed;
					inflator.avail_in = compressedSize;
					inflator.next_out = uncompressed;
					inflator.avail_out = uncompressedSize; 
					int err;
					if ((err = inflate (&inflator, Z_SYNC_FLUSH)) >= 0)
					{	
						uncompressedSize -= inflator.avail_out;
						if (crc32 (0, uncompressed, uncompressedSize) == crc_32)
						{
							i2p::data::netdb.AddRouterInfo (uncompressed, uncompressedSize);
							numFiles++;
						}	
						else
							LogPrint (eLogError, "Reseed: CRC32 verification failed");
					}	
					else
						LogPrint (eLogError, "Reseed: SU3 decompression error ", err);
					delete[] uncompressed;      
					inflateEnd (&inflator);
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
					LogPrint (eLogWarning, "Reseed: Missing zip central directory header");
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

	void Reseeder::LoadCertificate (const std::string& filename)
	{
		SSL_CTX * ctx = SSL_CTX_new (TLSv1_method ());
		int ret = SSL_CTX_use_certificate_file (ctx, filename.c_str (), SSL_FILETYPE_PEM); 
		if (ret)
		{	
			SSL * ssl = SSL_new (ctx);
			X509 * cert = SSL_get_certificate (ssl);
			// verify
			if (cert)
			{	
				// extract issuer name
				char name[100];
				X509_NAME_oneline (X509_get_issuer_name(cert), name, 100);
				// extract RSA key (we need n only, e = 65537)
				RSA * key = X509_get_pubkey (cert)->pkey.rsa;
				PublicKey value;
				i2p::crypto::bn2buf (key->n, value, 512);
				m_SigningKeys[name] = value;
			}	
			SSL_free (ssl);			
		}	
		else
			LogPrint (eLogError, "Reseed: Can't open certificate file ", filename);
		SSL_CTX_free (ctx);		
	}

	void Reseeder::LoadCertificates ()
	{
		std::string certDir = i2p::fs::DataDirPath("certificates", "reseed");
		std::vector<std::string> files;
		int numCertificates = 0;

		if (!i2p::fs::ReadDir(certDir, files)) {
			LogPrint(eLogWarning, "Reseed: Can't load reseed certificates from ", certDir);
			return;
		}

		for (const std::string & file : files) {
			if (file.compare(file.size() - 4, 4, ".crt") != 0) {
				LogPrint(eLogWarning, "Reseed: ignoring file ", file);
				continue;
			}
			LoadCertificate (file);
			numCertificates++;
		}	
		LogPrint (eLogInfo, "Reseed: ", numCertificates, " certificates loaded");
	}	

	std::string Reseeder::HttpsRequest (const std::string& address)
	{
		i2p::http::URL url;
		if (!url.parse(address)) {
			LogPrint(eLogError, "Reseed: failed to parse url: ", address);
			return "";
		}
		url.schema = "https";
		if (!url.port)
			url.port = 443;

		boost::asio::io_service service;
		boost::system::error_code ecode;
		auto it = boost::asio::ip::tcp::resolver(service).resolve (
			boost::asio::ip::tcp::resolver::query (url.host, std::to_string(url.port)), ecode);
		if (!ecode)
		{
			boost::asio::ssl::context ctx(service, boost::asio::ssl::context::sslv23);
			ctx.set_verify_mode(boost::asio::ssl::context::verify_none);
			boost::asio::ssl::stream<boost::asio::ip::tcp::socket> s(service, ctx);
			s.lowest_layer().connect (*it, ecode);
			if (!ecode)
			{
				s.handshake (boost::asio::ssl::stream_base::client, ecode);
				if (!ecode)
				{
					LogPrint (eLogDebug, "Reseed: Connected to ", url.host, ":", url.port);
					i2p::http::HTTPReq req;
					req.uri = url.to_string();
					req.add_header("User-Agent", "Wget/1.11.4");
					req.add_header("Connection", "close");
					s.write_some (boost::asio::buffer (req.to_string()));
					// read response
					std::stringstream rs;
					char recv_buf[1024]; size_t l = 0;
					do {
						l = s.read_some (boost::asio::buffer (recv_buf, sizeof(recv_buf)), ecode);
						if (l) rs.write (recv_buf, l);
					} while (!ecode && l);
					// process response
					std::string data = rs.str();
					i2p::http::HTTPRes res;
					int len = res.parse(data);
					if (len <= 0) {
						LogPrint(eLogWarning, "Reseed: incomplete/broken response from ", url.host);
						return "";
					}
					if (res.code != 200) {
						LogPrint(eLogError, "Reseed: failed to reseed from ", url.host, ", http code ", res.code);
						return "";
					}
					data.erase(0, len); /* drop http headers from response */
					LogPrint(eLogDebug, "Reseed: got ", data.length(), " bytes of data from ", url.host);
					if (res.is_chunked()) {
						std::stringstream in(data), out;
						if (!i2p::http::MergeChunkedResponse(in, out)) {
							LogPrint(eLogWarning, "Reseed: failed to merge chunked response from ", url.host);
							return "";
						}
						LogPrint(eLogDebug, "Reseed: got ", data.length(), "(", out.tellg(), ") bytes of data from ", url.host);
						data = out.str();
					}
					return data;
				}
				else
					LogPrint (eLogError, "Reseed: SSL handshake failed: ", ecode.message ());
			}
			else
				LogPrint (eLogError, "Reseed: Couldn't connect to ", url.host, ": ", ecode.message ());
		}
		else
			LogPrint (eLogError, "Reseed: Couldn't resolve address ", url.host, ": ", ecode.message ());
		return "";
	}	
}
}

