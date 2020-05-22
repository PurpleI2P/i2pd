/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <fstream>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/algorithm/string.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>

#include "Crypto.h"
#include "I2PEndian.h"
#include "Reseed.h"
#include "FS.h"
#include "Log.h"
#include "Identity.h"
#include "NetDb.hpp"
#include "HTTP.h"
#include "util.h"
#include "Config.h"

namespace i2p
{
namespace data
{

	Reseeder::Reseeder()
	{
	}

	Reseeder::~Reseeder()
	{
	}

	/**
	 @brief tries to bootstrap into I2P network (from local files and servers, with respect of options)
	 */
	void Reseeder::Bootstrap ()
	{
		std::string su3FileName; i2p::config::GetOption("reseed.file", su3FileName);
		std::string zipFileName; i2p::config::GetOption("reseed.zipfile", zipFileName);

		if (su3FileName.length() > 0) // bootstrap from SU3 file or URL
		{
			int num;
			if (su3FileName.length() > 8 && su3FileName.substr(0, 8) == "https://")
			{
				num = ReseedFromSU3Url (su3FileName); // from https URL
			}
			else
			{
				num = ProcessSU3File (su3FileName.c_str ());
			}
			if (num == 0)
				LogPrint (eLogWarning, "Reseed: failed to reseed from ", su3FileName);
		}
		else if (zipFileName.length() > 0) // bootstrap from ZIP file
		{
			int num = ProcessZIPFile (zipFileName.c_str ());
			if (num == 0)
				LogPrint (eLogWarning, "Reseed: failed to reseed from ", zipFileName);
		}
		else // bootstrap from reseed servers
		{
			int num = ReseedFromServers ();
			if (num == 0)
				LogPrint (eLogWarning, "Reseed: failed to reseed from servers");
		}
	}

	/**
	 * @brief bootstrap from random server, retry 10 times
	 * @return number of entries added to netDb
	 */
	int Reseeder::ReseedFromServers ()
	{
		std::string reseedURLs; i2p::config::GetOption("reseed.urls", reseedURLs);
		std::vector<std::string> httpsReseedHostList;
		boost::split(httpsReseedHostList, reseedURLs, boost::is_any_of(","), boost::token_compress_on);

		if (reseedURLs.length () == 0)
		{
			LogPrint (eLogWarning, "Reseed: No reseed servers specified");
			return 0;
		}

		int reseedRetries = 0;
		while (reseedRetries < 10)
		{
			auto ind = rand () % httpsReseedHostList.size ();
			std::string reseedUrl = httpsReseedHostList[ind] + "i2pseeds.su3";
			auto num = ReseedFromSU3Url (reseedUrl);
			if (num > 0) return num; // success
			reseedRetries++;
		}
		LogPrint (eLogWarning, "Reseed: failed to reseed from servers after 10 attempts");
		return 0;
	}

	/**
	 * @brief bootstrap from HTTPS URL with SU3 file
	 * @param url
	 * @return number of entries added to netDb
	 */
	int Reseeder::ReseedFromSU3Url (const std::string& url)
	{
		LogPrint (eLogInfo, "Reseed: Downloading SU3 from ", url);
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

	int Reseeder::ProcessZIPFile (const char * filename)
	{
		std::ifstream s(filename, std::ifstream::binary);
		if (s.is_open ())
		{
			s.seekg (0, std::ios::end);
			auto len = s.tellg ();
			s.seekg (0, std::ios::beg);
			return ProcessZIPStream (s, len);
		}
		else
		{
			LogPrint (eLogError, "Reseed: Can't open file ", filename);
			return 0;
		}
	}

	const char SU3_MAGIC_NUMBER[]="I2Psu3";
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

		bool verify; i2p::config::GetOption("reseed.verify", verify);
		if (verify)
		{
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
						BN_bin2bn (it->second, 512, n); // RSA 4096 assumed
						BN_mod_exp (s, s, i2p::crypto::GetRSAE (), n, bnctx); // s = s^e mod n
						uint8_t * enSigBuf = new uint8_t[signatureLength];
						i2p::crypto::bn2buf (s, enSigBuf, signatureLength);
						// digest is right aligned
						// we can't use RSA_verify due wrong padding in SU3
						if (memcmp (enSigBuf + (signatureLength - 64), digest, 64))
							LogPrint (eLogWarning, "Reseed: SU3 signature verification failed");
						else
							verify = false; // verified
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
		}

		if (verify) // not verified
		{
			LogPrint (eLogError, "Reseed: SU3 verification failed");
			return 0;
		}

		// handle content
		return ProcessZIPStream (s, contentLength);
	}

	const uint32_t ZIP_HEADER_SIGNATURE = 0x04034B50;
	const uint32_t ZIP_CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
	const uint16_t ZIP_BIT_FLAG_DATA_DESCRIPTOR = 0x0008;
	int Reseeder::ProcessZIPStream (std::istream& s, uint64_t contentLength)
	{
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
				// take care about data descriptor if presented
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

				LogPrint (eLogDebug, "Reseed: Processing file ", localFileName, " ", compressedSize, " bytes");
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
		if (numFiles) // check if routers are not outdated
		{
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			int numOutdated = 0;
			i2p::data::netdb.VisitRouterInfos (
				[&numOutdated, ts](std::shared_ptr<const RouterInfo> r)
				{
					if (r && ts > r->GetTimestamp () + 10*i2p::data::NETDB_MAX_EXPIRATION_TIMEOUT*1000LL) // 270 hours
					{
						LogPrint (eLogError, "Reseed: router ", r->GetIdentHash().ToBase64 (), " is outdated by ", (ts - r->GetTimestamp ())/1000LL/3600LL, " hours");
						numOutdated++;
					}
				});
			if (numOutdated > numFiles/2) // more than half
			{
				LogPrint (eLogError, "Reseed: mammoth's shit\n"
				"	   *_____*\n"
				"	  *_*****_*\n"
				"	 *_(O)_(O)_*\n"
				"	**____V____**\n"
				"	**_________**\n"
				"	**_________**\n"
				"	 *_________*\n"
				"	  ***___***");
				i2p::data::netdb.ClearRouterInfos ();
				numFiles = 0;
			}
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
		SSL_CTX * ctx = SSL_CTX_new (TLS_method ());
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
				char * cn = strstr (name, "CN=");
				if (cn)
				{
					cn += 3;
					char * terminator = strchr (cn, '/');
					if (terminator) terminator[0] = 0;
				}
				// extract RSA key (we need n only, e = 65537)
				RSA * key = EVP_PKEY_get0_RSA (X509_get_pubkey (cert));
				const BIGNUM * n, * e, * d;
				RSA_get0_key(key, &n, &e, &d);
				PublicKey value;
				i2p::crypto::bn2buf (n, value, 512);
				if (cn)
					m_SigningKeys[cn] = value;
				else
					LogPrint (eLogError, "Reseed: Can't find CN field in ", filename);
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
		i2p::http::URL proxyUrl;
		std::string proxy; i2p::config::GetOption("reseed.proxy", proxy);
		// check for proxy url
		if(proxy.size()) {
			// parse
			if(proxyUrl.parse(proxy)) {
				if (proxyUrl.schema == "http" && !proxyUrl.port) {
					proxyUrl.port = 80;
				} else if (proxyUrl.schema == "socks" && !proxyUrl.port) {
					proxyUrl.port = 1080;
				}
				// check for valid proxy url schema
				if (proxyUrl.schema != "http" && proxyUrl.schema != "socks") {
					LogPrint(eLogError, "Reseed: bad proxy url: ", proxy);
					return "";
				}
			} else {
				LogPrint(eLogError, "Reseed: bad proxy url: ", proxy);
				return "";
			}
		}
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

		boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
		ctx.set_verify_mode(boost::asio::ssl::context::verify_none);
		boost::asio::ssl::stream<boost::asio::ip::tcp::socket> s(service, ctx);

		if(proxyUrl.schema.size())
		{
			// proxy connection
			auto it = boost::asio::ip::tcp::resolver(service).resolve (
				boost::asio::ip::tcp::resolver::query (proxyUrl.host, std::to_string(proxyUrl.port)), ecode);
			if(!ecode)
			{
				s.lowest_layer().connect(*it, ecode);
				if(!ecode)
				{
					auto & sock = s.next_layer();
					if(proxyUrl.schema == "http")
					{
						i2p::http::HTTPReq proxyReq;
						i2p::http::HTTPRes proxyRes;
						proxyReq.method = "CONNECT";
						proxyReq.version = "HTTP/1.1";
						proxyReq.uri = url.host + ":" + std::to_string(url.port);

						boost::asio::streambuf writebuf, readbuf;

						std::ostream out(&writebuf);
						out << proxyReq.to_string();

						boost::asio::write(sock, writebuf.data(), boost::asio::transfer_all(), ecode);
						if (ecode)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: HTTP CONNECT write error: ", ecode.message());
							return "";
						}
						boost::asio::read_until(sock, readbuf, "\r\n\r\n", ecode);
						if (ecode)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: HTTP CONNECT read error: ", ecode.message());
							return "";
						}
						if(proxyRes.parse(boost::asio::buffer_cast<const char *>(readbuf.data()), readbuf.size()) <= 0)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: HTTP CONNECT malformed reply");
							return "";
						}
						if(proxyRes.code != 200)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: HTTP CONNECT got bad status: ", proxyRes.code);
							return "";
						}
					}
					else
					{
						// assume socks if not http, is checked before this for other types
						// TODO: support username/password auth etc
						uint8_t hs_writebuf[3] = {0x05, 0x01, 0x00};
						uint8_t hs_readbuf[2];
						boost::asio::write(sock, boost::asio::buffer(hs_writebuf, 3), boost::asio::transfer_all(), ecode);
						if(ecode)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: SOCKS handshake write failed: ", ecode.message());
							return "";
						}
						boost::asio::read(sock, boost::asio::buffer(hs_readbuf, 2), ecode);
						if(ecode)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: SOCKS handshake read failed: ", ecode.message());
							return "";
						}
						size_t sz = 0;
						uint8_t buf[256];

						buf[0] = 0x05;
						buf[1] = 0x01;
						buf[2] = 0x00;
						buf[3] = 0x03;
						sz += 4;
						size_t hostsz = url.host.size();
						if(1 + 2 + hostsz + sz > sizeof(buf))
						{
							sock.close();
							LogPrint(eLogError, "Reseed: SOCKS handshake failed, hostname too big: ", url.host);
							return "";
						}
						buf[4] = (uint8_t) hostsz;
						memcpy(buf+5, url.host.c_str(), hostsz);
						sz += hostsz + 1;
						htobe16buf(buf+sz, url.port);
						sz += 2;
						boost::asio::write(sock, boost::asio::buffer(buf, sz), boost::asio::transfer_all(), ecode);
						if(ecode)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: SOCKS handshake failed writing: ", ecode.message());
							return "";
						}
						boost::asio::read(sock, boost::asio::buffer(buf, 10), ecode);
						if(ecode)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: SOCKS handshake failed reading: ", ecode.message());
							return "";
						}
						if(buf[1] != 0x00)
						{
							sock.close();
							LogPrint(eLogError, "Reseed: SOCKS handshake bad reply code: ", std::to_string(buf[1]));
							return "";
						}
					}
				}
			}
		}
		else
		{
			// direct connection
			auto it = boost::asio::ip::tcp::resolver(service).resolve (
				boost::asio::ip::tcp::resolver::query (url.host, std::to_string(url.port)), ecode);
			if(!ecode)
				s.lowest_layer().connect (*it, ecode);
		}
		if (!ecode)
		{
			SSL_set_tlsext_host_name(s.native_handle(), url.host.c_str ());
			s.handshake (boost::asio::ssl::stream_base::client, ecode);
			if (!ecode)
			{
				LogPrint (eLogDebug, "Reseed: Connected to ", url.host, ":", url.port);
				i2p::http::HTTPReq req;
				req.uri = url.to_string();
				req.AddHeader("User-Agent", "Wget/1.11.4");
				req.AddHeader("Connection", "close");
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
		return "";
	}
}
}
