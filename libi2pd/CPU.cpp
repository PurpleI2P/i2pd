/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "CPU.h"
#include "Log.h"

namespace i2p
{
namespace cpu
{
	bool aesni = false;

	void Detect(bool AesSwitch, bool force)
	{
#if defined(__x86_64__) || defined(__i386__)
		__builtin_cpu_init ();
#if defined (_WIN32) && (WINVER == 0x0501) // WinXP
		if (AesSwitch && force) { // only if forced
#else
		if ((__builtin_cpu_supports ("aes") && AesSwitch) || (AesSwitch && force)) {
#endif
			aesni = true;
		}
#endif
		LogPrint(eLogInfo, "AESNI ", (aesni ? "enabled" : "disabled"));
	}
}
}
