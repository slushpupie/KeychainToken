/*
 *  support_funcs.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/7/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#ifndef _SUPPORT_FUNCS_H_
#define _SUPPORT_FUNCS_H_

#include <Security/cssm.h>
#include <openssl/x509.h>

#include "mypkcs11.h"
#include "types.h"
#include "debug.h"
#include "preferences.h"


#include "mypkcs11.h"
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



int isCertDuplicated(sessionEntry *session, objectEntry *object);
void addObject(sessionEntry *session, objectEntry *object);
void removeObject(sessionEntry *session, objectEntry *object);
void freeAllObjects(sessionEntry *session);
void freeObject(objectEntry *object);

objectEntry * makeObjectFromCertificateRef(SecCertificateRef certRef, CK_OBJECT_CLASS class);
objectEntry * makeObjectFromIdRef(SecIdentityRef idRef, CK_OBJECT_CLASS class);
objectEntry * getObject(sessionEntry *session, CK_OBJECT_HANDLE hObject);

void addObjectToSearchResults(sessionEntry *session, objectEntry *object);
void removeObjectFromSearchResults(sessionEntry *session, objectEntry *object);
void freeObjectSearchList(sessionEntry *session);

CK_RV getAttributeValueCertificate(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV getAttributeValuePublicKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV getAttributeValuePrivateKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV findObjectsInitCertificate(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV findObjectsInitPublicKey(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV findObjectsInitPrivateKey(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

void setString(char *in, char *out, int len);
char * basename(const char *input);
void setDateFromASN1Time(const ASN1_TIME *aTime, char *out);

#endif