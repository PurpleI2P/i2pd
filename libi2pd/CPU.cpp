/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "CPU.h"
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#include "Log.h"

#ifndef bit_AES
#define bit_AES (1 << 25)
#endif
#ifndef bit_AVX
#define bit_AVX (1 << 28)
#endif


namespace i2p
{
namespace cpu
{
	bool aesni = false;
	bool avx = false;

	void Detect()
	{
#if defined(__AES__) || defined(__AVX__)

#if defined(__x86_64__) || defined(__i386__)
		int info[4];
		__cpuid(0, info[0], info[1], info[2], info[3]);
		if (info[0] >= 0x00000001) {
			__cpuid(0x00000001, info[0], info[1], info[2], info[3]);
#ifdef __AES__
			aesni = info[2] & bit_AES;  // AESNI
#endif  // __AES__
#ifdef __AVX__
			avx = info[2] & bit_AVX;  // AVX
#endif  // __AVX__
		}
#endif  // defined(__x86_64__) || defined(__i386__)

#ifdef __AES__
		if(aesni)
		{
			LogPrint(eLogInfo, "AESNI enabled");
		}
#endif  // __AES__
#ifdef __AVX__
		if(avx)
		{
			LogPrint(eLogInfo, "AVX enabled");
		}
#endif  // __AVX__
#endif  // defined(__AES__) || defined(__AVX__)
	}
}
}
