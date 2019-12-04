#ifndef ELLIGATOR_H__
#define ELLIGATOR_H__

#include <memory>

namespace i2p
{
namespace crypto
{

	class Elligator2
	{
		public:

			Elligator2 ();
			~Elligator2 ();
	};

	std::unique_ptr<Elligator2>& GetElligator ();
}
}

#endif


