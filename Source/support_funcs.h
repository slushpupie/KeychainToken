/*
 *  support_funcs.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/7/09.
 *  Copyright 2009,2016
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef _SUPPORT_FUNCS_H_
#define _SUPPORT_FUNCS_H_

#include <Security/cssm.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "pkcs11.h"
#include "types.h"
#include "debug.h"
#include "preferences.h"


#include "pkcs11.h"
#include "types.h"
#include "constants.h"

#include "debug.h"
#include "preferences.h"

extern CK_BBOOL initialized;
extern SecKeychainRef keychainSlots[MAX_SLOTS];
extern sessionEntry *firstSession;
extern CK_SESSION_HANDLE sessionCounter;
extern mutexFunctions mutex;

unsigned int updateSlotList();

sessionEntry * findSessionEntry(CK_SESSION_HANDLE hSession);
void addSession(sessionEntry * newSession);
void removeSession(CK_SESSION_HANDLE hSession);

int isDuplicated(sessionEntry *session, objectEntry *object);
void addObject(sessionEntry *session, objectEntry *object);
void removeObject(sessionEntry *session, objectEntry *object);
void freeAllObjects(sessionEntry *session);
void freeObject(objectEntry *object);

objectEntry * makeObjectFromCertificateRef(SecCertificateRef certRef, SecKeychainRef keychain, CK_OBJECT_CLASS class);
objectEntry * makeObjectFromKeyRef(SecKeyRef keyRef, SecKeychainRef keychain, CK_OBJECT_CLASS class);
objectEntry * makeObjectFromIdRef(SecIdentityRef idRef, CK_OBJECT_CLASS class);
objectEntry * getObject(sessionEntry *session, CK_OBJECT_HANDLE hObject);

OSStatus getPublicKeyRefForObject(objectEntry *object, SecKeyRef *publicKeyRef);

void addObjectToSearchResults(sessionEntry *session, objectEntry *object);
void removeObjectFromSearchResults(sessionEntry *session, objectEntry *object);
void freeObjectSearchList(sessionEntry *session);

CK_RV getAttributeValueCertificate(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV getAttributeValuePublicKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV getAttributeValuePrivateKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

void setString(char *in, char *out, int len);
void setDateFromASN1Time(const ASN1_TIME *aTime, char *out);

CSSM_ALGORITHMS pMechanismToCSSM_ALGID(CK_MECHANISM_PTR pMechanism);

#endif
