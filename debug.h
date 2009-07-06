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

void debug(int level, const char* format, ...);
const char * getCKRName(CK_RV rv);
char *hexify(unsigned char *data, int len);
char *stringify(unsigned char *str, int length);

#endif