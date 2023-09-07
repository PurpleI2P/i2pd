/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "CPU.h"
#include "Log.h"

#ifndef bit_AES
	#define bit_AES (1 << 25)
#endif

#if (defined(__GNUC__) && __GNUC__ < 5)
	#include <cpuid.h>
#endif

#ifdef _MSC_VER
	#include <intrin.h>
#endif

namespace i2p
{
namespace cpu
{
	bool aesni = false;

	inline bool cpu_support_aes()
	{
#if (defined(_M_AMD64) || defined(__x86_64__)) || (defined(_M_IX86) || defined(__i386__))
#	if (defined(__GNUC__) && __GNUC__ > 4)
#		warning("CPU: IN GCC!!!")
		__builtin_cpu_init();
		return __builtin_cpu_supports("aes");
#	elif (defined(__clang__) && !defined(__GNUC__))
#		warning("CPU: IN CLANG!!!")
#		warning(__clang__)
#		if (__clang_major__ >= 6)
		__builtin_cpu_init();
#		endif
		return __builtin_cpu_supports("aes");
#	elif (defined(_MSC_VER) || (defined(__GNUC__) && __GNUC__ < 5))
#		warning("CPU: IN MSVC!!!")
		int cpu_info[4];
		__cpuid(cpu_info, 1);
		return ((cpu_info[2] & bit_AES) != 0);
#	else
#		warning("CPU: FALSE")
		return false;
#	endif
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
