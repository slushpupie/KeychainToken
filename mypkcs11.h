/*
 *  mypkcs11.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/23/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#ifndef MYPKCS11_H
#define MYPKCS11_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv,func) rv func
#define CK_DECLARE_FUNCTION_POINTER(rv,func) rv (* func)
#define CK_CALLBACK_FUNCTION(rv,func) rv (* func)
#define CK_NULL_PTR 0

#include "pkcs11.h"
#include "pkcs11n.h"

#endif


