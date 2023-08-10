/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef LIBI2PD_CPU_H
#define LIBI2PD_CPU_H

namespace i2p
{
namespace cpu
{
	extern bool aesni;

	void Detect(bool AesSwitch, bool force);
}
}

#endif
