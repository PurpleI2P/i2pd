/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "CPU.h"
#include "Log.h"

#if defined(_MSC_VER)
#include <intrin.h>

#ifndef bit_AES
	#define bit_AES (1 << 25)
#endif
#endif

namespace i2p
{
namespace cpu
{
	bool aesni = false;

	inline bool cpu_support_aes()
	{
#if (_M_AMD64 || __x86_64__) || (_M_IX86 || __i386__)
#if defined(_MSC_VER)
		int cpu_info[4];
		__cpuid(cpu_info, 1);
		return ((cpu_info[2] & bit_AES) != 0)
#elif defined(__clang__)
#if __clang_major__ >= 6
		__builtin_cpu_init();
#endif
		return __builtin_cpu_supports("aes");
#elif defined(__GNUC__)
		__builtin_cpu_init();
		return __builtin_cpu_supports("aes");
#else
		return false;
#endif
#else
		return false;
#endif
	}

	void Detect(bool AesSwitch, bool force)
	{
		if ((cpu_support_aes() && AesSwitch) || (AesSwitch && force)) {
			aesni = true;
		}

		LogPrint(eLogInfo, "AESNI ", (aesni ? "enabled" : "disabled"));
	}
}
}
