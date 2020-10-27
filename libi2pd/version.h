/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef _VERSION_H_
#define _VERSION_H_

#define CODENAME "Purple"

#define STRINGIZE(x) #x
#define MAKE_VERSION(a,b,c) STRINGIZE(a) "." STRINGIZE(b) "." STRINGIZE(c)
#define MAKE_VERSION_NUMBER(a,b,c) ((a*100+b)*100+c)

#define I2PD_VERSION_MAJOR 2
#define I2PD_VERSION_MINOR 34
#define I2PD_VERSION_MICRO 0
#define I2PD_VERSION_PATCH 0
#define I2PD_VERSION MAKE_VERSION(I2PD_VERSION_MAJOR, I2PD_VERSION_MINOR, I2PD_VERSION_MICRO)
#define VERSION I2PD_VERSION

#ifdef MESHNET
#define I2PD_NET_ID 3
#else
#define I2PD_NET_ID 2
#endif

#define I2P_VERSION_MAJOR 0
#define I2P_VERSION_MINOR 9
#define I2P_VERSION_MICRO 47
#define I2P_VERSION_PATCH 0
#define I2P_VERSION MAKE_VERSION(I2P_VERSION_MAJOR, I2P_VERSION_MINOR, I2P_VERSION_MICRO)
#define I2P_VERSION_NUMBER MAKE_VERSION_NUMBER(I2P_VERSION_MAJOR, I2P_VERSION_MINOR, I2P_VERSION_MICRO)

#endif
