/*
 *  debug.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/1/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdlib.h>
#include <string.h>

#include "mypkcs11.h"



#define DEBUG_CRITICAL  1
#define DEBUG_WARNING   2
#define DEBUG_IMPORTANT 3
#define DEBUG_INFO      4
#define DEBUG_VERBOSE   5

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL DEBUG_CRITICAL
#endif



void debug(int level, const char* format, ...);

const char * getCKRName(CK_RV rv);
const char * getCKAName(CK_ATTRIBUTE_TYPE attrib);
const char * getCKOName(CK_OBJECT_CLASS class);
const char * getCKMName(CK_MECHANISM_TYPE mech);
const char * getCKCName(CK_CERTIFICATE_TYPE ctype);
const char * getSecErrorName(OSStatus status);
char *hexify(unsigned char *data, int len);
char *stringify(unsigned char *str, int length);

#endif