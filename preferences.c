/*
 *  preferences.c
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/26/09.
 *  Copyright 2009
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "preferences.h"

// Note: If not NULL the results have to be DisposePtr'ed.
static char* Copy_CFStringRefToCString(const CFStringRef pCFStringRef)
{
    char* results = NULL;

    if (NULL != pCFStringRef)
    {
        CFIndex length = sizeof(UniChar) * CFStringGetLength(pCFStringRef) + 1;

        results = (char*) NewPtrClear(length);
        if (!CFStringGetCString(pCFStringRef,results,length,kCFStringEncodingASCII))
        {
            if (!CFStringGetCString(pCFStringRef,results,length,kCFStringEncodingUTF8))
            {
                DisposePtr(results);
                results = NULL;
            }
        }
    }
    return results;
}


#define kAppCFStr CFSTR("com.slushpupie.KeychainToken")



int isKeychainListed(char *keychainPath, char *listName) {




    CFArrayRef    prefCFArrayRef = CFPreferencesCopyAppValue( CFStringCreateWithCString(NULL, listName, kCFStringEncodingASCII), kAppCFStr);
    CFIndex       blacklist,index;
    int           blacklisted = 0;

    if (NULL == prefCFArrayRef)
        return 0;

    blacklist = CFArrayGetCount(prefCFArrayRef);

    for (index = 0;index < blacklist;index++) {
        CFStringRef    keychainCFString;
        char*        keychainStrPtr;




        keychainCFString = CFArrayGetValueAtIndex(prefCFArrayRef,index);
        if (NULL == keychainCFString)
            break;

        keychainStrPtr = Copy_CFStringRefToCString(keychainCFString);

        if(strcmp(keychainPath,keychainStrPtr) == 0) {
            blacklisted = 1;
            DisposePtr(keychainStrPtr);
            break;
        }
        DisposePtr(keychainStrPtr);

    }

    CFRelease(prefCFArrayRef);

    return blacklisted;
}

int isKeychainBlacklisted(char *keychainPath) {
    return isKeychainListed(keychainPath, "blacklist");
}

int isKeychainWhitelisted(char *keychainPath) {
    return isKeychainListed(keychainPath, "whitelist");
}

int isKeychainGreylisted(char *keychainPath) {
    return isKeychainListed(keychainPath, "greylist");
}

int useWhitelist() {
    CFArrayRef    prefCFArrayRef = CFPreferencesCopyAppValue( CFStringCreateWithCString(NULL, "whitelist", kCFStringEncodingASCII), kAppCFStr);

    if (NULL == prefCFArrayRef)
        return 0;

    CFRelease(prefCFArrayRef);
    return 1;

}
