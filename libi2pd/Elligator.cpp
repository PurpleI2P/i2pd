#include "Elligator.h"

namespace i2p
{
namespace crypto
{
	Elligator2::Elligator2 ()
	{
	}

	Elligator2::~Elligator2 ()
	{
	}

	static std::unique_ptr<Elligator2> g_Elligator;
	std::unique_ptr<Elligator2>& GetElligator ()
	{
		if (!g_Elligator)
		{
			auto el = new Elligator2();
			if (!g_Elligator) // make sure it was not created already
				g_Elligator.reset (el);
			else
				delete el;
		}
		return g_Elligator;
	}
}
}

