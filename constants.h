/*
 *  constants.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/7/09.
 *  Copyright 2009 All rights reserved.
 *
 */



#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

#define MIN(m,n) ((m) < (n) ? (m) : (n))
#define MAX(m,n) ((m) > (n) ? (m) : (n))

#define MAX_SLOTS 10
#define MAX_KEYCHAIN_PATH_LEN 2048
#define KEYID_SIZE SHA_DIGEST_LENGTH

#endif
