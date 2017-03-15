#ifndef GOST_H__
#define GOST_H__

#include <memory>
#include <openssl/ec.h>

namespace i2p
{
namespace crypto
{

	// ГОСТ Р 34.10
	
	enum GOSTR3410ParamSet
	{
		// GOST R 34.10-2001
		eGOSTR3410CryptoProA = 0,   // 1.2.643.2.2.35.1
		eGOSTR3410CryptoProB,	    // 1.2.643.2.2.35.2
		eGOSTR3410CryptoProC,	    // 1.2.643.2.2.35.3
		// XchA = A, XchB = C
		//eGOSTR3410CryptoProXchA,    // 1.2.643.2.2.36.0
		//eGOSTR3410CryptoProXchB,	// 1.2.643.2.2.36.1
		// GOST R 34.10-2012		
		eGOSTR3410TC26A256,		// 1.2.643.7.1.2.1.1.1 
		eGOSTR3410TC26C512,		// 1.2.643.7.1.2.1.2.3 
		eGOSTR3410NumParamSets
	};	
	
	class GOSTR3410Curve
	{
		public:

			GOSTR3410Curve (BIGNUM * a, BIGNUM * b, BIGNUM * p, BIGNUM * q, BIGNUM * x, BIGNUM * y);
			~GOSTR3410Curve ();			

			size_t GetKeyLen () const { return m_KeyLen; }; 
			EC_POINT * MulP (const BIGNUM * n) const;
			bool GetXY (const EC_POINT * p, BIGNUM * x, BIGNUM * y) const;
			EC_POINT * CreatePoint (const BIGNUM * x, const BIGNUM * y) const;
			void Sign (const BIGNUM * priv, const BIGNUM * digest, BIGNUM * r, BIGNUM * s);
			bool Verify (const EC_POINT * pub, const BIGNUM * digest, const BIGNUM * r, const BIGNUM * s);
			
		private:

			EC_GROUP * m_Group;
			size_t m_KeyLen; // in bytes
	};

	std::unique_ptr<GOSTR3410Curve>& GetGOSTR3410Curve (GOSTR3410ParamSet paramSet);
}
}

#endif
