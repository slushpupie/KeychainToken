/*
 *  preferences.c
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/26/09.
 *  Copyright 2009 All rights reserved.
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


#define kAppCFStr CFSTR("com.apple.KeychainToken")



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

