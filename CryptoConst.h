#ifndef CRYPTO_CONST_H__
#define CRYPTO_CONST_H__

#include <cryptopp/integer.h>

namespace i2p
{
namespace crypto
{
	// DH
	
	inline const CryptoPP::Integer& get_elgp ()
	{ 
		static const CryptoPP::Integer elgp_ (
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" 
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
								"h");
		return elgp_;
	}
	#define elgp get_elgp()

	inline const CryptoPP::Integer& get_elgg ()
	{
		static const CryptoPP::Integer elgg_ (2); 
		return elgg_;
	}
	#define elgg get_elgg()	

	// DSA
	inline const CryptoPP::Integer& get_dsap ()
	{
		static const CryptoPP::Integer dsap_ (
			"9c05b2aa960d9b97b8931963c9cc9e8c3026e9b8ed92fad0a69cc886d5bf8015fcadae31" 
			"a0ad18fab3f01b00a358de237655c4964afaa2b337e96ad316b9fb1cc564b5aec5b69a9f"
			"f6c3e4548707fef8503d91dd8602e867e6d35d2235c1869ce2479c3b9d5401de04e0727f"
			"b33d6511285d4cf29538d9e3b6051f5b22cc1c93"
			                      "h"); 
		return dsap_;
	}
	#define dsap get_dsap()			

	inline const CryptoPP::Integer& get_dsaq ()
	{
		static const CryptoPP::Integer dsaq_ (
			"a5dfc28fef4ca1e286744cd8eed9d29d684046b7"                          
			                      "h");
		return dsaq_;
	}
	#define dsaq get_dsaq()	
	
	inline const CryptoPP::Integer& get_dsag ()
	{
		static const CryptoPP::Integer dsag_ (
			"c1f4d27d40093b429e962d7223824e0bbc47e7c832a39236fc683af84889581075ff9082"
			"ed32353d4374d7301cda1d23c431f4698599dda02451824ff369752593647cc3ddc197de"
			"985e43d136cdcfc6bd5409cd2f450821142a5e6f8eb1c3ab5d0484b8129fcf17bce4f7f3"
			"3321c3cb3dbb14a905e7b2b3e93be4708cbcc82"                          
			                      "h");
		return dsag_;
	}
	#define dsag get_dsag()	
}		
}	

#endif
