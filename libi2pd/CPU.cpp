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

	void Detect(bool AesSwitch, bool AvxSwitch, bool force)
	{
#if defined(__x86_64__) || defined(__i386__)
		int info[4];
		__cpuid(0, info[0], info[1], info[2], info[3]);
		if (info[0] >= 0x00000001) {
			__cpuid(0x00000001, info[0], info[1], info[2], info[3]);
#if defined (_WIN32) && (WINVER == 0x0501) // WinXP
			if (AesSwitch && force) { // only if forced
#else
			if ((info[2] & bit_AES && AesSwitch) || (AesSwitch && force)) {
#endif
				aesni = true;
			}
#if defined (_WIN32) && (WINVER == 0x0501) // WinXP
			if (AvxSwitch && force) { // only if forced
#else
			if ((info[2] & bit_AVX && AvxSwitch) || (AvxSwitch && force)) {
#endif
				avx = true;
			}
		}
#endif // defined(__x86_64__) || defined(__i386__)

		LogPrint(eLogInfo, "AESNI ", (aesni ? "enabled" : "disabled"));
		LogPrint(eLogInfo, "AVX ", (avx ? "enabled" : "disabled"));
	}
}
}
