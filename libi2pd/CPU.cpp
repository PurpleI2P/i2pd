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

#if defined(__GNUC__) && __GNUC__ < 6 && IS_X86
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
#if IS_X86
#if defined(__clang__)
#	if (__clang_major__ >= 6)
		__builtin_cpu_init();
#	endif
		return __builtin_cpu_supports("aes");
#elif (defined(__GNUC__) && __GNUC__ >= 6)
		__builtin_cpu_init();
		return __builtin_cpu_supports("aes");
#elif (defined(__GNUC__) && __GNUC__ < 6)
		int cpu_info[4];
		bool flag = false;
		__cpuid(0, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
		if (cpu_info[0] >= 0x00000001) {
			__cpuid(0x00000001, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
			flag = ((cpu_info[2] & bit_AES) != 0);
		}
		return flag;
#elif defined(_MSC_VER)
		int cpu_info[4];
		__cpuid(cpu_info, 1);
		return ((cpu_info[2] & bit_AES) != 0);
#endif
#endif
		return false;
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
