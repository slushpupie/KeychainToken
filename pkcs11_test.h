/*
 *  pkcs11_test.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/24/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#ifndef _PKCS11_TEST_H_
#define _PKCS11_TEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mypkcs11.h"
#include "debug.h"

#ifndef _WIN32
#include <termios.h>
#include <dlfcn.h>
#define GetFuncFromMod dlsym
#define CloseMod dlclose
typedef void *LpHandleType;
#else
#include <io.h>
#define GetFuncFromMod GetProcAddress
#define CloseMod FreeLibrary
typedef HINSTANCE LpHandleType;
#endif


void hexdump(unsigned char *, int);
CK_RV get_slot(CK_FUNCTION_LIST_PTR, CK_SLOT_ID_PTR);
CK_RV login(CK_FUNCTION_LIST_PTR, CK_SESSION_HANDLE, int, CK_UTF8CHAR *, CK_ULONG);
CK_RV load_library(char *, CK_FUNCTION_LIST_PTR *);
char *unhex(char *input, CK_ULONG *length);
CK_RV getPassword(CK_UTF8CHAR *pass, CK_ULONG *length);


#endif