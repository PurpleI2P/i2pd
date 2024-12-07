/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef LIBI2PD_CPU_H
#define LIBI2PD_CPU_H

#if defined(_M_AMD64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
#	define IS_X86 1
#	if defined(_M_AMD64) || defined(__x86_64__)
#		define IS_X86_64 1
#	else
#		define IS_X86_64 0
#	endif
#else
#	define IS_X86 0
#	define IS_X86_64 0
#endif

#endif
