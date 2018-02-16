#include "CPU.h"
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#include "Log.h"
namespace i2p
{
namespace cpu
{
	bool aesni = false;
	bool avx = false;

	void Detect()
	{
#if defined(__x86_64__) || defined(__i386__)
		int info[4];
		__cpuid(0, info[0], info[1], info[2], info[3]);
		if (info[0] >= 0x00000001) {
			__cpuid(0x00000001, info[0], info[1], info[2], info[3]);
			aesni = info[2] & bit_AES;  // AESNI
			avx = info[2] & bit_AVX;  // AVX
		}
#endif
		if(aesni)
		{
			LogPrint(eLogInfo, "AESNI enabled");
		}
		if(avx)
		{
			LogPrint(eLogInfo, "AVX enabled");
		}
	}
}
}
