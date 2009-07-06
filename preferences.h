/*
 *  preferences.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/26/09.
 *  Copyright 2009 All rights reserved.
 *
 */


#ifndef _PREFERENCES_H_
#define _PREFERENCES_H_

#include <Carbon/Carbon.h>
#include <CoreFoundation/CFPreferences.h>
#include <CoreServices/CoreServices.h>

int isKeychainBlacklisted(char *keychainPath);
int isKeychainWhitelisted(char *keychainPath);
int isKeychainGreylisted(char *keychainPath);
int useWhitelist();


#endif