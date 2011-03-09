/*
 *  globals.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/7/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#ifndef _TYPES_H_
#define _TYPES_H_
#include "constants.h"

typedef struct _certObjectEntry {
    SecIdentityRef idRef;
    SecCertificateRef certRef;
    unsigned char keyId[KEYID_SIZE];
    X509 *x509;
    
    int havePrivateKey;
} certObjectEntry;

typedef struct _pubKeyObjectEntry {
    SecIdentityRef idRef;
    SecKeyRef keyRef;
    unsigned char keyId[KEYID_SIZE];
    EVP_PKEY *pubKey;
    
} pubKeyObjectEntry;

typedef struct _privKeyObjectEntry {
    SecIdentityRef idRef;
    SecKeyRef keyRef;
    unsigned char keyId[KEYID_SIZE];
    X509 *x509;
    
} privKeyObjectEntry;

typedef struct _objectEntry {
    CK_OBJECT_HANDLE id;
    CK_OBJECT_CLASS class;
    CK_ATTRIBUTE    *pTemplate;
    CK_ULONG        templateSize;
    CSSM_DATA label;
    
    struct _objectEntry *nextObject;
    
    union storage_t {
        certObjectEntry certificate;
        pubKeyObjectEntry publicKey;
        privKeyObjectEntry privateKey;
    } storage;
    
} objectEntry;

typedef struct _objectSearchEntry {
    objectEntry *object;
    struct _objectSearchEntry *next;
} objectSearchEntry;


typedef struct _sessionEntry {
    CK_SESSION_HANDLE id;
    CK_FLAGS flags;
    CK_STATE state;
    CK_SLOT_ID slot;
    bool loggedIn;
    
    CK_ATTRIBUTE_PTR searchFilter;
    CK_ULONG searchFilter_count;
    
    objectEntry *objectList;
    CK_OBJECT_HANDLE objectCounter;
    
    objectSearchEntry *searchList;
    objectSearchEntry *cursor;
    
    CK_ULONG keyIdCounter;
    
    CSSM_CC_HANDLE  encryptContext;
    CSSM_CC_HANDLE  decryptContext;
    CSSM_CC_HANDLE  signContext;
    CSSM_CC_HANDLE  verifyContext;
    
    CSSM_ALGORITHMS signAlgorithm;

    CK_VOID_PTR myMutex;
    
    struct _sessionEntry *nextSession;
} sessionEntry;

typedef struct _mechInfo {
    CK_MECHANISM_TYPE mech;
    CK_MECHANISM_INFO info;
} mechInfo;

typedef struct _mutex_functions {
    bool use;
    CK_CREATEMUTEX CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX LockMutex;
    CK_UNLOCKMUTEX UnlockMutex;
    
    CK_VOID_PTR slotMutex;
    CK_VOID_PTR sessionMutex;
    
} mutexFunctions;




#endif
