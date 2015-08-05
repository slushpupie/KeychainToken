/*
 *  globals.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/7/09.
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

#ifndef _TYPES_H_
#define _TYPES_H_
#include "constants.h"

typedef struct _certObjectEntry {
    SecIdentityRef idRef;
    SecCertificateRef certRef;
    X509 *x509;

    int havePrivateKey;
} certObjectEntry;

typedef struct _pubKeyObjectEntry {
    SecIdentityRef idRef;
    SecKeyRef keyRef;
    EVP_PKEY *pubKey;

} pubKeyObjectEntry;

typedef struct _privKeyObjectEntry {
    SecIdentityRef idRef;
    SecKeyRef keyRef;
    X509 *x509;

} privKeyObjectEntry;

typedef struct _objectEntry {
    CK_OBJECT_HANDLE id;
    CK_OBJECT_CLASS class;
    CK_ATTRIBUTE    *pTemplate;
    CK_ULONG        templateSize;
    CSSM_DATA keyId; //used for CKA_ID
    CSSM_DATA label; //used for CKA_LABEL


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
