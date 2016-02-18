#include <openssl/ssl.h>
#include <openssl/evp.h>
#include "util.h"
#include "Log.h"
#include "Family.h"

namespace i2p
{
namespace data
{
	Families::Families ()
	{
	}

	Families::~Families ()
	{
	}

	void Families::LoadCertificate (const std::string& filename)
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
				auto pkey = X509_get_pubkey (cert);
				int keyType = EVP_PKEY_type(pkey->type);
				switch (keyType)
				{
					case EVP_PKEY_DSA:
						// TODO:
					break;
					case EVP_PKEY_EC:
					{
						//EC_KEY * ecKey = EVP_PKEY_get0_EC_KEY (pkey);
						break;
					}
					default:
						LogPrint (eLogWarning, "Family: Certificate key type ", keyType, " is not supported");
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
		boost::filesystem::path familyDir = i2p::util::filesystem::GetCertificatesDir() / "family";
		
		if (!boost::filesystem::exists (familyDir)) return;
		int numCertificates = 0;
		boost::filesystem::directory_iterator end; // empty
		for (boost::filesystem::directory_iterator it (familyDir); it != end; ++it)
		{
			if (boost::filesystem::is_regular_file (it->status()) && it->path ().extension () == ".crt")
			{	
				LoadCertificate (it->path ().string ());
				numCertificates++;
			}	
		}	
		if (numCertificates > 0)
			LogPrint (eLogInfo, "Family: ", numCertificates, " certificates loaded");
	}
}
}

