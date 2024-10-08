/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <openssl/ssl.h>
#include "Crypto.h"
#include "FS.h"
#include "Log.h"
#include "Family.h"
#include "Config.h"

namespace i2p
{
namespace data
{
	Families::Families ()
	{
	}

	Families::~Families ()
	{
		for (auto it : m_SigningKeys)
			if (it.second.first) EVP_PKEY_free (it.second.first);
	}

	void Families::LoadCertificate (const std::string& filename)
	{
		SSL_CTX * ctx = SSL_CTX_new (TLS_method ());
		int ret = SSL_CTX_use_certificate_file (ctx, filename.c_str (), SSL_FILETYPE_PEM);
		if (ret)
		{
			SSL * ssl = SSL_new (ctx);
			X509 * cert = SSL_get_certificate (ssl);
			if (cert)
			{
				std::shared_ptr<i2p::crypto::Verifier> verifier;
				// extract issuer name
				char name[100];
				X509_NAME_oneline (X509_get_issuer_name(cert), name, 100);
				char * cn = strstr (name, "CN=");
				if (cn)
				{
					cn += 3;
					char * family = strstr (cn, ".family");
					if (family) family[0] = 0;
					auto pkey = X509_get_pubkey (cert);
					if (pkey)
					{	
						if (!m_SigningKeys.emplace (cn, std::make_pair(pkey, (int)m_SigningKeys.size () + 1)).second)
						{
							EVP_PKEY_free (pkey);
							LogPrint (eLogError, "Family: Duplicated family name ", cn);
						}	
					}	
				}
			}
			SSL_free (ssl);
		}
		else
			LogPrint (eLogError, "Family: Can't open certificate file ", filename);
		SSL_CTX_free (ctx);
	}

	void Families::LoadCertificates ()
	{
		std::string certDir = i2p::fs::GetCertsDir() + i2p::fs::dirSep + "family";

		std::vector<std::string> files;
		int numCertificates = 0;

		if (!i2p::fs::ReadDir(certDir, files)) {
			LogPrint(eLogWarning, "Family: Can't load family certificates from ", certDir);
			return;
		}

		for (const std::string & file : files) {
			if (file.compare(file.size() - 4, 4, ".crt") != 0) {
				LogPrint(eLogWarning, "Family: ignoring file ", file);
				continue;
			}
			LoadCertificate (file);
			numCertificates++;
		}
		LogPrint (eLogInfo, "Family: ", numCertificates, " certificates loaded");
	}

	bool Families::VerifyFamily (const std::string& family, const IdentHash& ident,
		const char * signature, const char * key) const
	{
		uint8_t buf[100], signatureBuf[64];
		size_t len = family.length (), signatureLen = strlen (signature);
		if (len + 32 > 100)
		{
			LogPrint (eLogError, "Family: ", family, " is too long");
			return false;
		}
		auto it = m_SigningKeys.find (family);
		if (it != m_SigningKeys.end () && it->second.first)
		{	
			memcpy (buf, family.c_str (), len);
			memcpy (buf + len, (const uint8_t *)ident, 32);
			len += 32;
			auto signatureBufLen = Base64ToByteStream (signature, signatureLen, signatureBuf, 64);
			if (signatureBufLen)
			{
				EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
				EVP_DigestVerifyInit (ctx, NULL, NULL, NULL, it->second.first);
				auto ret = EVP_DigestVerify (ctx, signatureBuf, signatureBufLen, buf, len);
				EVP_MD_CTX_destroy (ctx);
				return ret;
			}	
		}	
		// TODO: process key
		return true;
	}

	FamilyID Families::GetFamilyID (const std::string& family) const
	{
		auto it = m_SigningKeys.find (family);
		if (it != m_SigningKeys.end ())
			return it->second.second;
		return 0;
	}

	std::string CreateFamilySignature (const std::string& family, const IdentHash& ident)
	{
		auto filename = i2p::fs::DataDirPath("family", (family + ".key"));
		std::string sig;
		SSL_CTX * ctx = SSL_CTX_new (TLS_method ());
		int ret = SSL_CTX_use_PrivateKey_file (ctx, filename.c_str (), SSL_FILETYPE_PEM);
		if (ret)
		{
			SSL * ssl = SSL_new (ctx);
			auto pkey = SSL_get_privatekey (ssl);
			if (pkey)
			{
				uint8_t buf[100], signature[128];
				size_t len = family.length ();
				memcpy (buf, family.c_str (), len);
				memcpy (buf + len, (const uint8_t *)ident, 32);
				len += 32;
				size_t l = 128;
				EVP_MD_CTX * mdctx = EVP_MD_CTX_create ();
				EVP_DigestSignInit (mdctx, NULL, NULL, NULL, pkey);
				if (EVP_DigestSign (mdctx, signature, &l, buf, len))
				{
					len = Base64EncodingBufferSize (l);
					char * b64 = new char[len+1];
					len = ByteStreamToBase64 (signature, l, b64, len);
					b64[len] = 0;
					sig = b64;
					delete[] b64;
				}	
				else		
					LogPrint (eLogError, "Family: signing failed");
				EVP_MD_CTX_destroy (mdctx);
			}	
			SSL_free (ssl);
		}
		else
			LogPrint (eLogError, "Family: Can't open keys file: ", filename);
		SSL_CTX_free (ctx);
		return sig;
	}
}
}
