/*
 *  support_funcs.c
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/7/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#include "support_funcs.h"

unsigned int    
updateSlotList()
{
    OSStatus status = 0;
    CFArrayRef kcSrchList = NULL;
    unsigned int found = 0;
    unsigned int i,j,whitelist;
    
    
    whitelist = useWhitelist();
    
    status = SecKeychainCopySearchList(&kcSrchList);
    if (status != 0) {
        debug(DEBUG_WARNING, "%s: Failed to copy keychain search list\n", __FUNCTION__);
        return 0;
    }
    
    for(i = 0; i < MAX_SLOTS; i++) {
        if(keychainSlots[i] != NULL) {
            CFRelease(keychainSlots[i]);
            keychainSlots[i] = NULL;
        }
    }
    
    if (CFGetTypeID(kcSrchList) == SecKeychainGetTypeID()) {
        keychainSlots[0] = (SecKeychainRef) kcSrchList;
        return 1;
    } else {
        CFArrayRef array = (CFArrayRef) kcSrchList;
        found = CFArrayGetCount(array);
        if(found > MAX_SLOTS) {
            //oops!
            found = MAX_SLOTS;
        }
        
        for(i = 0,j=0; i < found; i++) {
            char keychainName[MAX_KEYCHAIN_PATH_LEN];
            UInt32 keychainLen = sizeof(keychainName) - 1;
            memset(keychainName, 0, sizeof(keychainName));
            status = SecKeychainGetPath((SecKeychainRef)CFArrayGetValueAtIndex(array, i), &keychainLen, keychainName);
            
            
            if (status != 0) {
                continue;
            }
            
            debug(DEBUG_VERBOSE, "Keychain %s ", keychainName);
                  
            if(useWhitelist()) {
                if(isKeychainWhitelisted(keychainName) || isKeychainGreylisted(keychainName)) {
                    keychainSlots[j++] = (SecKeychainRef) CFArrayGetValueAtIndex(array, i);
                    debug(DEBUG_VERBOSE, "listed");
                }
            } else {
                if(!isKeychainBlacklisted(keychainName)) {
                    keychainSlots[j++] = (SecKeychainRef) CFArrayGetValueAtIndex(array,i);
                    debug(DEBUG_VERBOSE, "listed");
                }
            }
            debug(DEBUG_VERBOSE,"\n");
        }
        
        return j;
        
    }
}

/*
 * Searching for CK_INVALID_HANDLE will return the last sessionEntry in the linked list
 */
sessionEntry *
findSessionEntry(CK_SESSION_HANDLE hSession) 
{
    sessionEntry *cur, *prev;
    
    cur = firstSession;
    prev = NULL;
    while(cur != NULL) {
        
        if(cur->id == hSession) {
            return cur;
        }
        prev = cur;
        cur = cur->nextSession;
    }
    if(hSession == CK_INVALID_HANDLE) {
        return prev;
    } else {
        return NULL;
    }
    
}

void
addSession(sessionEntry *newSession) 
{
    sessionEntry *last;
    
    last = findSessionEntry(CK_INVALID_HANDLE);
    if(last == NULL) {
        firstSession = newSession;
    } else {
        last->nextSession = newSession;
    }
}

void 
removeSession(CK_SESSION_HANDLE hSession)
{
    sessionEntry *cur, *prev;
    
    if(firstSession == NULL) {
        return;
    }
    
    
    
    cur = firstSession;
    prev = NULL;
    while(cur != NULL) {
        
        if(cur->id == hSession) {
            if(cur == firstSession) {
                firstSession = cur->nextSession;
            } else {
                prev->nextSession = cur->nextSession;
            }
            
            freeObjectSearchList(cur);
            freeAllObjects(cur);
            
            if(mutex.use) {
                mutex.DestroyMutex(cur->myMutex);
            }
            
            free(cur);
            return;
        }
        prev = cur;
        cur = cur->nextSession;
    }
    
    return;
}

int
isCertDuplicated(sessionEntry *session, objectEntry *object) 
{
    objectEntry *cur;
    
    if(session->objectList == NULL) {
        return 0;
    }
    
    cur = session->objectList;
    while(cur->nextObject != NULL) {
        if(cur->class == CKO_CERTIFICATE) {
            if(cur->storage.certificate.certRef == object->storage.certificate.certRef) {
                return 1;
            }
        }
        cur = cur->nextObject;
    }
    
    return (cur->storage.certificate.certRef == object->storage.certificate.certRef);
}

void
addObject(sessionEntry *session, objectEntry *object) 
{
    objectEntry *cur;
    
    object->id = session->objectCounter++;
    debug(DEBUG_VERBOSE,"Adding object %u\n",object->id);
    if(session->objectList == NULL) {
        session->objectList = object;
        object->nextObject = NULL;
        return;
    }
    
    cur = session->objectList;
    while(cur->nextObject != NULL) {
        cur = cur->nextObject;
    }
    cur->nextObject = object;
    object->nextObject = NULL;
    
}

void
removeObject(sessionEntry *session, objectEntry *object) 
{
    objectEntry *cur, *prev;
    
    if(session == NULL)
        return;
    
    if(object == NULL) 
        return;
    
    cur = session->objectList;
    prev = NULL;
    while(cur != NULL) {
        if(cur == object) {
            if(cur == session->objectList) {
                session->objectList = cur->nextObject;
            } else {
                prev->nextObject = cur->nextObject;
            }
            freeObject(cur);
            return;
        }
        prev = cur;
        cur = cur->nextObject;
    }
    
}

void
freeAllObjects(sessionEntry *session) 
{
    objectEntry *cur,*next;
    
    debug(DEBUG_VERBOSE,"Freeing all objects for session\n");
    cur = session->objectList;
    
    while(cur !=NULL) {
        next = cur->nextObject;
        freeObject(cur);
        cur = next;
    }
    
    session->objectList = NULL;
    session->cursor = NULL;
}

void
freeObject(objectEntry *object) 
{
    if(object == NULL)
        return;
    debug(DEBUG_VERBOSE," Deleting object %u\n",object->id);
    
    /* First free up any internal data */
    switch(object->class) {
        case CKO_DATA:
            break;
        case CKO_CERTIFICATE:
            CFRelease(object->storage.certificate.certRef);
            if(object->storage.certificate.idRef)
                CFRelease(object->storage.certificate.idRef);
            break;
        case CKO_PUBLIC_KEY:
            CFRelease(object->storage.publicKey.keyRef);
            if(object->storage.publicKey.idRef)
                CFRelease(object->storage.publicKey.idRef);
            break;
        case CKO_PRIVATE_KEY:
            CFRelease(object->storage.privateKey.keyRef);
            if(object->storage.privateKey.idRef)
                CFRelease(object->storage.privateKey.idRef);
            break;
        case CKO_SECRET_KEY:
        case CKO_HW_FEATURE:
        case CKO_DOMAIN_PARAMETERS:
        case CKO_MECHANISM:
        case CKO_OTP_KEY:
            break;
            
    }
    free(object);
}

objectEntry *
makeObjectFromCertificateRef(SecCertificateRef certRef, CK_OBJECT_CLASS class) 
{
    objectEntry *object = NULL;
    OSStatus status;
    CSSM_DATA certData;
    unsigned char *pData;
    unsigned char digest[SHA_DIGEST_LENGTH];
    
    status = SecCertificateGetData(certRef, &certData);
    if (status != 0) {
        return NULL;
    }
    pData = certData.Data;
    
    SHA1(certData.Data, certData.Length, digest);
    
    
    object = malloc(sizeof(objectEntry));
    if(!object) {
        return NULL;
    }
    memset(object, 0, sizeof(objectEntry));
    object->class = class;
    
    switch(class) {
        case CKO_CERTIFICATE:
            object->storage.certificate.x509 = d2i_X509(NULL, (void *) &pData, certData.Length);
            if(!object->storage.certificate.x509) {
                debug(DEBUG_IMPORTANT,"OpenSSL failed to parse certificate\n");
                free(object);
                return NULL;
            }
            object->storage.certificate.certRef = certRef;
            memcpy(object->storage.certificate.keyId,digest,SHA_DIGEST_LENGTH);
            CFRetain(object->storage.certificate.certRef);
            return object;
            
        case CKO_PUBLIC_KEY:
            
            
            status = SecCertificateCopyPublicKey(certRef, &(object->storage.publicKey.keyRef));
            if (status != 0) {
                free(object);
                return NULL;
            }
			memcpy(object->storage.publicKey.keyId,digest,SHA_DIGEST_LENGTH);
            
            CFRetain(object->storage.publicKey.keyRef);
            return object;
    }
    
    free(object);
    return NULL;
}

objectEntry *
makeObjectFromIdRef(SecIdentityRef idRef, CK_OBJECT_CLASS class) 
{
    objectEntry *object = NULL;
    OSStatus status;
    SecCertificateRef certRef;
    CSSM_DATA certData;
    unsigned char *pData;
    unsigned char digest[SHA_DIGEST_LENGTH];
    
    status = SecIdentityCopyCertificate(idRef, &certRef);
    if (status != 0) {
        return NULL;
    }
    
    status = SecCertificateGetData(certRef, &certData);
    if (status != 0) {
        return NULL;
    }
    pData = certData.Data;
    
    
    SHA1(certData.Data, certData.Length, digest);
    
    
    object = malloc(sizeof(objectEntry));
    if(!object) {
        return NULL;
    }
    memset(object, 0, sizeof(objectEntry));
    object->class = class;
    
    switch(class) {
        case CKO_CERTIFICATE:
            object->storage.certificate.x509 = d2i_X509(NULL, (void *) &pData, certData.Length);
            if(!object->storage.certificate.x509) {
                debug(DEBUG_IMPORTANT,"OpenSSL failed to parse certificate\n");
                free(object);
                return NULL;
            }
            object->storage.certificate.certRef = certRef;
            object->storage.certificate.idRef = idRef;
            object->storage.certificate.havePrivateKey = 1;
            memcpy(object->storage.certificate.keyId,digest,SHA_DIGEST_LENGTH);
            CFRetain(object->storage.certificate.certRef);
            CFRetain(object->storage.certificate.idRef);
            return object;
            
        case CKO_PUBLIC_KEY:
            status = SecCertificateCopyPublicKey(certRef, &(object->storage.publicKey.keyRef));
            if (status != 0) {
                free(object);
                return NULL;
            }
            object->storage.publicKey.idRef= idRef;
            memcpy(object->storage.publicKey.keyId,digest,SHA_DIGEST_LENGTH);
            CFRetain(object->storage.publicKey.keyRef);
            CFRetain(object->storage.publicKey.idRef);
            return object;
            
        case CKO_PRIVATE_KEY:
            object->storage.certificate.x509 = d2i_X509(NULL, (void *) &pData, certData.Length);
            if(!object->storage.certificate.x509) {
                debug(DEBUG_IMPORTANT,"OpenSSL failed to parse certificate\n");
                free(object);
                return NULL;
            }
            
            status = SecIdentityCopyPrivateKey(idRef, &(object->storage.privateKey.keyRef));
            if (status != 0) {
                free(object);
                return NULL;
            }
            debug(DEBUG_VERBOSE,"*PrivateKey SecKeyRef=0x%X\n",object->storage.privateKey.keyRef);
            object->storage.privateKey.idRef = idRef;
            memcpy(object->storage.privateKey.keyId,digest,SHA_DIGEST_LENGTH);
            CFRetain(object->storage.privateKey.keyRef);
            CFRetain(object->storage.privateKey.idRef);
            
            return object;
            
    }
    free(object);
    return NULL;
}

objectEntry * 
getObject(sessionEntry *session, CK_OBJECT_HANDLE hObject) 
{
    objectEntry *object;
    
    object = session->objectList;
    debug(DEBUG_VERBOSE,"Requested object id %u\n",hObject);
    
    while(object != NULL) {
        if(object->id == hObject) {
            return object;
        }
        object = object->nextObject;
    }
    
    return NULL;
}

OSStatus
getPublicKeyRefForObject(objectEntry *object, SecKeyRef *publicKeyRef)
{
    OSStatus status = -1;
	
    if(object && publicKeyRef)
    {
        // get the right keyref and CSP for the public key
        // (cf. http://lists.apple.com/archives/apple-cdsa/2007/Aug/msg00014.html )
        switch(object->class)  
        {
            case CKO_CERTIFICATE:
                // in case of a certificate get the public key ref
                status = SecCertificateCopyPublicKey(object->storage.certificate.certRef, publicKeyRef);
                if(status != 0)  
                {
                    debug(DEBUG_WARNING,"Error in SecCertificateCopyPublicKey\n");
                }
                break;
            case CKO_PUBLIC_KEY:
                *publicKeyRef = object->storage.publicKey.keyRef;
                status = 0;
                break;
            default:
                debug(DEBUG_IMPORTANT,"Object must be certificate or private key\n");
        }
    }
    return status;
}

void
addObjectToSearchResults(sessionEntry *session, objectEntry *object) 
{
    
    if(session->searchList == NULL) {
        session->searchList = malloc(sizeof(objectSearchEntry));
        memset(session->searchList, 0, sizeof(objectSearchEntry));
        session->searchList->object = object;
        session->searchList->next = NULL;
        session->cursor = session->searchList;
    } else {
        session->cursor = session->searchList;
        while(session->cursor->next != NULL) {
            session->cursor = session->cursor->next;
        }
        session->cursor->next = malloc(sizeof(objectSearchEntry));
        memset(session->cursor->next, 0, sizeof(objectSearchEntry));
        session->cursor = session->cursor->next;
        session->cursor->object = object;
        session->cursor->next = NULL;
    }
}

void
removeObjectFromSearchResults(sessionEntry *session, objectEntry *object)
{
    objectSearchEntry *previous = NULL;
    objectSearchEntry *next = NULL;
    
    if(session->searchList == NULL) {
        return;
    }
    
    session->cursor = session->searchList;
    previous = NULL;
    while(session->cursor != NULL) {
        next = session->cursor->next;
        
        if(session->cursor->object == object) {
            if(session->cursor == session->searchList) {
                /* First in the list */
                session->searchList = session->cursor->next;
            } else {
                previous->next = session->cursor->next;
            }
            free(session->cursor);
        } else {
            previous = session->cursor;
        }
        session->cursor = next;
    }
}

void
freeObjectSearchList(sessionEntry *session)
{
    if(session->searchList == NULL) {
        return;
    }
    
    session->cursor = session->searchList;
    
    while(session->cursor != NULL) {
        removeObjectFromSearchResults(session, session->cursor->object);
    }
    session->searchList = NULL;
    session->cursor = NULL;
}

CK_RV
getAttributeValueCertificate(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
    CK_ULONG i = 0;
    CK_RV rv = CKR_OK;
    CSSM_DATA certData;
    unsigned char *pData;
    OSStatus status = 0;
    int n = 0;
    
    SecCertificateGetData(object->storage.certificate.certRef, &certData);
    if (status != 0) {
        debug(DEBUG_IMPORTANT,"Error getting certificate data");
        return CKR_GENERAL_ERROR;
    }
    pData = certData.Data;
    
    debug(DEBUG_VERBOSE,"Getting certificate attributes\n");
    for (i = 0 ; i < ulCount; i++) {
        switch (pTemplate[i].type) {
                
                
            case CKA_CLASS:
                debug(DEBUG_VERBOSE,"  CKA_CLASS\n");
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(object->class)) {
                        memcpy(pTemplate[i].pValue, &object->class, sizeof(object->class));
                        debug(DEBUG_VERBOSE,"    0x%X (%s)\n", object->class, getCKOName(object->class) );
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = sizeof(object->class);
                break;
                
            case CKA_TOKEN:
                debug(DEBUG_VERBOSE,"  CKA_TOKEN\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL t = CK_TRUE;
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &t, sizeof(CK_BBOOL));
                        debug(DEBUG_VERBOSE,"    %X\n",t);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
                
            case CKA_PRIVATE:
                debug(DEBUG_VERBOSE,"  CKA_PRIVATE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL f = CK_FALSE;
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                        debug(DEBUG_VERBOSE,"    %X\n",f);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
                
            case CKA_MODIFIABLE:
                debug(DEBUG_VERBOSE,"  CKA_MODIFIABLE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL f = CK_FALSE;
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                        debug(DEBUG_VERBOSE,"    %X\n",f);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
                
            case CKA_LABEL:
                debug(DEBUG_VERBOSE,"  CKA_LABEL\n");
            {
#if 0
                
                char *sn = X509_NAME_oneline(object->storage.certificate.x509->cert_info->subject, NULL, 256);
                
                
                n = strlen(sn);
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        memcpy(pTemplate[i].pValue, sn, n); /*not null terminated*/
                        debug(DEBUG_VERBOSE,"    %s\n",sn);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = n;
#else
                
                char *sn = X509_NAME_oneline(object->storage.certificate.x509->cert_info->subject, NULL, 256);
                char tag[] = "(  )";
                
                
                int m = strlen(sn);
                int n = strlen(tag);
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= m + n) {
                        memcpy(pTemplate[i].pValue, sn, m); /*not null terminated*/
                        sprintf(tag,"(%02d)",object->id);
                        memcpy(pTemplate[i].pValue+m, tag, n);
                        debug(DEBUG_VERBOSE,"    %s%s\n",sn,tag);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = m+n;
                
#endif
                
                
                
            }
                break;
                
                
                
                
            case CKA_CERTIFICATE_TYPE:
                debug(DEBUG_VERBOSE,"  CKA_CERTIFICATE_TYPE\n");
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_CERTIFICATE_TYPE)) {
                        CK_CERTIFICATE_TYPE certType = CKC_X_509;
                        memcpy(pTemplate[i].pValue, &certType, sizeof(CK_CERTIFICATE_TYPE));
                        debug(DEBUG_VERBOSE,"    0x%X (%s)\n",certType, getCKCName(certType));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
                break;
                
            case CKA_TRUSTED:
                debug(DEBUG_VERBOSE,"  CKA_TRUSTED\n");
                if(object->storage.certificate.havePrivateKey) {
                    if(pTemplate[i].pValue != NULL) {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            CK_BBOOL trusted = CK_TRUE;
                            memcpy(pTemplate[i].pValue, &trusted, sizeof(CK_BBOOL));
                            debug(DEBUG_VERBOSE,"    %X\n",trusted);
                        } else {
                            rv = CKR_BUFFER_TOO_SMALL;
                        }
                    } else {
                        debug(DEBUG_VERBOSE,"    sizerequest\n");
                    }
                    pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                }
                
                break;
                
            case CKA_CERTIFICATE_CATEGORY:
                debug(DEBUG_VERBOSE,"  CKA_CERTIFICATE_CATEGORY\n");
                /* 0 = unspecified (default)
                 * 1 = token user (priv-key availible)
                 * 2 = CA cert
                 * 3 = other
                 */
                if(object->storage.certificate.havePrivateKey) {
                    if(pTemplate[i].pValue != NULL) {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
                            CK_ULONG certCat = 1;
                            memcpy(pTemplate[i].pValue, &certCat, sizeof(CK_ULONG));
                            debug(DEBUG_VERBOSE,"    %X\n",certCat);
                        } else {
                            rv = CKR_BUFFER_TOO_SMALL;
                        }
                    } else {
                        debug(DEBUG_VERBOSE,"    sizerequest\n");
                    }
                    pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                }
                break;
                
            case CKA_CHECK_VALUE:
                debug(DEBUG_VERBOSE,"  CKA_CHECK_VALUE\n");
                /* The value of this attribute is derived from the certificate by 
                 * taking the first three bytes of the SHA-1 hash of the certificate
                 * object’s CKA_VALUE attribute. 
                 *
                 * Since we use the SHA-1 of the certificate as the CKA_ID we already
                 * have the value and don't need to compute it again. 
                 */
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= 3) {
                        memcpy(pTemplate[i].pValue, object->storage.certificate.keyId, 3);
                        debug(DEBUG_VERBOSE,"    %X\n",pTemplate[i].pValue);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = 3;
                break;
                
            case CKA_START_DATE:
                debug(DEBUG_VERBOSE,"  CKA_START_DATE\n");
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= 8) {
                        setDateFromASN1Time(object->storage.certificate.x509->cert_info->validity->notBefore, pTemplate[i].pValue);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = 8;
                break;
                
            case CKA_END_DATE:
                debug(DEBUG_VERBOSE,"  CKA_END_DATE\n");
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= 8) {
                        setDateFromASN1Time(object->storage.certificate.x509->cert_info->validity->notAfter, pTemplate[i].pValue);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = 8;
                break;
                
            case CKA_SUBJECT:
                debug(DEBUG_VERBOSE,"  CKA_SUBJECT\n");
                /* DER-encoded certificate subject name */
                n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->subject, NULL);
                
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->subject, (unsigned char **) &(pTemplate[i].pValue));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = n;
                
                break;
                
            case CKA_ID:
                debug(DEBUG_VERBOSE,"  CKA_ID\n");
                /* Key identifier for pub/pri keypair */
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= SHA_DIGEST_LENGTH) {
                        debug(DEBUG_VERBOSE,"     %s\n",hexify(object->storage.certificate.keyId, SHA_DIGEST_LENGTH));
                        memcpy(pTemplate[i].pValue, &object->storage.certificate.keyId, SHA_DIGEST_LENGTH);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = SHA_DIGEST_LENGTH;
                
                break;
                
            case CKA_ISSUER:
                debug(DEBUG_VERBOSE,"  CKA_ISSUER\n");
                /* DER-encoded certificate issuer name */
                n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->issuer, NULL);
                
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->issuer, (unsigned char **) &(pTemplate[i].pValue));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = n;
                
                break;
                
            case CKA_SERIAL_NUMBER:
                debug(DEBUG_VERBOSE,"  CKA_SERIAL_NUMBER\n");
                /* DER-encoded certificate serial number */
                n = i2d_ASN1_INTEGER(object->storage.certificate.x509->cert_info->serialNumber, NULL);
                
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        n = i2d_ASN1_INTEGER(object->storage.certificate.x509->cert_info->serialNumber, (unsigned char **) &(pTemplate[i].pValue));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = n;
                
                break;
                
            case CKA_VALUE:
                debug(DEBUG_VERBOSE,"  CKA_VALUE\n");
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= certData.Length) {
                        memcpy(pTemplate[i].pValue, certData.Data, certData.Length);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = certData.Length;
                
                break;
                
                
            case CKA_URL:
                debug(DEBUG_VERBOSE,"  CKA_URL\n");
                /* RFC2279 string of the URL where certificate can be obtained */
                if (object->class != CKO_CERTIFICATE) {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
                debug(DEBUG_VERBOSE,"  CKA_HASH_OF_SUBJECT_PUBLIC_KEY\n");
                /* SHA-1 hash of the subject public key */
                if (object->class != CKO_CERTIFICATE) {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
                debug(DEBUG_VERBOSE,"  CKA_HASH_OF_ISSUER_PUBLIC_KEY\n");
                /* SHA-1 hash of the issuer public key */
                if (object->class != CKO_CERTIFICATE) {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_JAVA_MIDP_SECURITY_DOMAIN:
                debug(DEBUG_VERBOSE,"  CKA_JAVA_MIDP_SECURITY_DOMAIN\n");
                /* Java MIDP security domain:
                 * 0 = unspecified
                 * 1 = manufacturer
                 * 2 = operator
                 * 3 = 3rd party
                 */
                if (object->class != CKO_CERTIFICATE) {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_NSS_EMAIL:
                debug(DEBUG_VERBOSE,"  CKA_NSS_EMAIL\n");
                /* Not supported */
                pTemplate[i].ulValueLen = -1;
                break;
                
            default:
                debug(DEBUG_VERBOSE,"Unknown CKO_CERTIFICATE attribute requested: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                
        }
    }
    return rv;
}

CK_RV
getAttributeValuePublicKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    /*TODO: Many of the attributes can be obtained from the CSSM Key: cssmKey->KeyHeader->KeyAttr,KeyUsage,etc */
    CK_ULONG i = 0;
    CK_RV rv = CKR_OK;
    
    for (i = 0 ; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(object->class)) {
                        memcpy(pTemplate[i].pValue, &object->class, sizeof(object->class));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(object->class);
                break; 
                
            case CKA_TOKEN:
            case CKA_PRIVATE:
            case CKA_MODIFIABLE:
            case CKA_LABEL:
                break;
                
            case CKA_KEY_TYPE:
            {
                //TODO determine key type:
                CK_KEY_TYPE keyType = CKK_RSA;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                        memcpy(pTemplate[i].pValue, &keyType, sizeof(CK_KEY_TYPE));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                break;
            }   
            case CKA_ID:
                /* Key identifier for key */
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= SHA_DIGEST_LENGTH) {
                        memcpy(pTemplate[i].pValue, &object->storage.publicKey.keyId, SHA_DIGEST_LENGTH);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = SHA_DIGEST_LENGTH;
                break;
            case CKA_START_DATE:
                //TODO
                break;
            case CKA_END_DATE:
                //TODO
                break;
            case CKA_DERIVE:
            {
                CK_BBOOL f = CK_FALSE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            }
            case CKA_LOCAL:
            {
                CK_BBOOL t = CK_TRUE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &t, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            } 
            case CKA_KEY_GEN_MECHANISM:
                //TODO
                /* Identifier of the mechanim used to generate the key material */
                break;
            case CKA_ALLOWED_MECHANISMS:
                //TODO
                /* a list of mechanisms alloed to be used with this key */
                break;
                
            case CKA_SUBJECT:
                //TODO
                /* DER-encoded subject name */
                break;
            case CKA_ENCRYPT:
                //TODO
                /* true if this key supports encryption */
                break;
            case CKA_VERIFY:
                //TODO
                /* true if this key supports verification */
                break;
            case CKA_VERIFY_RECOVER:
                //TODO
                /* true if this key supports verification where data is recoverd from signature */
                break;
            case CKA_WRAP:
                //TODO
                /* true if this key supports wrapping */
                break;
            case CKA_TRUSTED:
                //TODO
                break;
            case CKA_WRAP_TEMPLATE:
                //TODO
                /* For wrapping keys. The attribute to match against any keys
                 * wrapped using this wrapping key. Keys that do not match cannot
                 * be wrapped. 
                 */
                break;
                
            case CKA_MODULUS:
            {
                CK_ULONG len = 0;
                EVP_PKEY *rsa = NULL;
                rsa = X509_get_pubkey(object->storage.publicKey.x509);
                
                if (!rsa) {
					rv = CKR_ATTRIBUTE_TYPE_INVALID;
				} else {
					len = BN_num_bytes(rsa->pkey.rsa->n);
					if(pTemplate[i].pValue != NULL) {
						if(pTemplate[i].ulValueLen >= len) {
							len = BN_bn2bin(rsa->pkey.rsa->n, (unsigned char *) pTemplate[i].pValue);
						} else {
							rv = CKR_BUFFER_TOO_SMALL;
						}
					}
					pTemplate[i].ulValueLen = len;
				}
            }         
                break;
            case CKA_MODULUS_BITS: 
            {
                CK_ULONG len = 0;
                EVP_PKEY *rsa = NULL;
                rsa = X509_get_pubkey(object->storage.publicKey.x509);
                
                len = BN_num_bits(rsa->pkey.rsa->n);
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
                        memcpy(pTemplate[i].pValue, &len, sizeof(CK_ULONG));
                        
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } 
                pTemplate[i].ulValueLen = sizeof(CK_ULONG);
            }
                break;
            case CKA_PUBLIC_EXPONENT: 
            {
                CK_ULONG len = 0;
                EVP_PKEY *rsa = NULL;
                rsa = X509_get_pubkey(object->storage.publicKey.x509);
                
                len = BN_num_bits(rsa->pkey.rsa->e);
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= len) {
                        len = BN_bn2bin(rsa->pkey.rsa->e, (unsigned char *) pTemplate[i].pValue);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } 
                pTemplate[i].ulValueLen = len;
            }         
                break;    
            default:
                pTemplate[i].ulValueLen = -1;
                debug(DEBUG_INFO,"Unknown CKO_PUBLIC_KEY attribute requested: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                
                
        }
    }
    return rv;
}

CK_RV
getAttributeValuePrivateKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
    /*TODO: Many of the attributes can be obtained from the CSSM Key: cssmKey->KeyHeader->KeyAttr,KeyUsage,etc */
    CK_ULONG i = 0;
    CK_RV rv = CKR_OK;
    
    for (i = 0 ; i < ulCount; i++) {
        debug(DEBUG_VERBOSE,"  %s (0x%X)\n",getCKAName(pTemplate[i].type), pTemplate[i].type);
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(object->class)) {
                        memcpy(pTemplate[i].pValue, &object->class, sizeof(object->class));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(object->class);
                break; 
                
            case CKA_TOKEN:
            case CKA_PRIVATE:
            case CKA_MODIFIABLE:
                break;
            case CKA_LABEL:
            {
                char *sn = X509_NAME_oneline(object->storage.certificate.x509->cert_info->subject, NULL, 256);
                char tag[] = "(  )";
                
                
                int m = strlen(sn);
                int n = strlen(tag);
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= m + n) {
                        memcpy(pTemplate[i].pValue, sn, m); /*not null terminated*/
                        sprintf(tag,"(%02d)",object->id);
                        memcpy(pTemplate[i].pValue+m, tag, n);
                        debug(DEBUG_VERBOSE,"    %s%s\n",sn,tag);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } else {
                    debug(DEBUG_VERBOSE,"    sizerequest\n");
                }
                pTemplate[i].ulValueLen = m+n;
            }
                break;
                
            case CKA_KEY_TYPE:
            {
                //TODO determine key type:
                CK_KEY_TYPE keyType = CKK_RSA;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_KEY_TYPE)) {
                        memcpy(pTemplate[i].pValue, &keyType, sizeof(CK_KEY_TYPE));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                break;
            }   
            case CKA_ID:
                /* Key identifier for key */
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= SHA_DIGEST_LENGTH) {
                        debug(DEBUG_VERBOSE,"     %s\n",hexify(object->storage.privateKey.keyId, SHA_DIGEST_LENGTH));
                        memcpy(pTemplate[i].pValue, &object->storage.privateKey.keyId, SHA_DIGEST_LENGTH);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = SHA_DIGEST_LENGTH;
                break;
                
            case CKA_START_DATE:
                //TODO
                break;
                
            case CKA_END_DATE:
                //TODO
                break;
                
            case CKA_DERIVE:
            {
                CK_BBOOL f = CK_FALSE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            }
                
            case CKA_LOCAL:
            {
                CK_BBOOL t = CK_TRUE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &t, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            } 
            case CKA_KEY_GEN_MECHANISM:
                //TODO
                /* Identifier of the mechanim used to generate the key material */
                break;
            case CKA_ALLOWED_MECHANISMS:
                //TODO
                /* a list of mechanisms alloed to be used with this key */
                break;
            case CKA_SUBJECT:
                //TODO
                /* DER-encoded subject name */
                break;
            case CKA_SENSITIVE:
                //TODO
                /* true if this key is sensitive */
                break;
            case CKA_DECRYPT:
                //TODO
                /* true if this key supports decryption */
                break;
            case CKA_SIGN:
                //TODO
                /* true if this key supports signing */
                break;
            case CKA_SIGN_RECOVER:
                //TODO
                /* true if this key supports signing where data is recoverd from signature */
                break;
            case CKA_UNWRAP:
                //TODO
                /* true if this key supports unwrapping */
                break;
            case CKA_EXTRACTABLE:
                /* true if this key is extractable */
            {
                CK_BBOOL f = CK_FALSE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            }
                break;
            case CKA_ALWAYS_SENSITIVE:
                //TODO
                /* true if this key has always been sensitive */
                break;
            case CKA_NEVER_EXTRACTABLE:
                /* true if this key has never been marked extractable */
            {
                CK_BBOOL t = CK_TRUE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &t, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            }
            case CKA_WRAP_WITH_TRUSTED:
                /* true if this key can only be wrapped with a wrapping key that has CKA_TRUSTED set true */
            {
                CK_BBOOL f = CK_FALSE;
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
            }
            case CKA_UNWRAP_TEMPLATE:
                //TODO
                /* For wrapping keys. */
                
                
            case CKA_ALWAYS_AUTHENTICATE:
                //TODO
                /* true if the user must enter a pin for each use of this key */
                break;
                
            case CKA_MODULUS:
            {
                CK_ULONG len = 0;
                EVP_PKEY *rsa = NULL;
                rsa = X509_get_pubkey(object->storage.privateKey.x509);
                
                
                len = BN_num_bytes(rsa->pkey.rsa->n);
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= len) {
                        len = BN_bn2bin(rsa->pkey.rsa->n, (unsigned char *) pTemplate[i].pValue);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } 
                pTemplate[i].ulValueLen = len;
            }         
                break;
            case CKA_MODULUS_BITS: 
            {
                CK_ULONG len = 0;
                EVP_PKEY *rsa = NULL;
                rsa = X509_get_pubkey(object->storage.privateKey.x509);
                
                len = BN_num_bits(rsa->pkey.rsa->n);
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
                        memcpy(pTemplate[i].pValue, &len, sizeof(CK_ULONG));
                        
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } 
                pTemplate[i].ulValueLen = sizeof(CK_ULONG);
            }
                break;
            case CKA_PUBLIC_EXPONENT: 
            {
                CK_ULONG len = 0;
                EVP_PKEY *rsa = NULL;
                rsa = X509_get_pubkey(object->storage.privateKey.x509);
                
                len = BN_num_bits(rsa->pkey.rsa->e);
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= len) {
                        len = BN_bn2bin(rsa->pkey.rsa->e, (unsigned char *) pTemplate[i].pValue);
                    } else {
                        rv = CKR_BUFFER_TOO_SMALL;
                    }
                } 
                pTemplate[i].ulValueLen = len;
            }         
                break;
            default:
                pTemplate[i].ulValueLen = -1;
                debug(DEBUG_IMPORTANT,"Unknown CKO_PUBLIC_KEY attribute requested: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
                
        }
    }
    return rv;
}

CK_RV
findObjectsInitCertificate(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    objectEntry *object = NULL;
    CK_ULONG i = 0;
    int n = 0;
    
    debug(DEBUG_VERBOSE,"CKO_CERTIFICATE (0x%X)\n", CKO_CERTIFICATE);
    
    if(session->objectList == NULL) {
        session->searchList = NULL;
        session->cursor = NULL;
        return CKR_OK;
    }
    
    /* add all cert objects to search results, then remove based on tempalte */
    object = session->objectList;
    while(object != NULL) {
        if(object->class == CKO_CERTIFICATE) {
            addObjectToSearchResults(session,object);
        }
        object = object->nextObject;
    }
    
    if(session->objectList == NULL) {
        session->searchList = NULL;
        session->cursor = NULL;
        return CKR_OK;
    }
    
    for(i = 0; i < ulCount; i++) {
        switch(pTemplate[i].type) {
            case CKA_CLASS:
                //already handled
                break;
                
            case CKA_TOKEN:
                debug(DEBUG_VERBOSE,"  CKA_TOKEN\n");
                
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL token = CK_TRUE;
                    memcpy(&token, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(token == CK_FALSE) {
                        //all objects on this token are token objects
                        freeObjectSearchList(session);
                        return CKR_OK;
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
                
            case CKA_PRIVATE:
                debug(DEBUG_VERBOSE,"  CKA_PRIVATE\n");
                
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL private = CK_TRUE;
                    memcpy(&private, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(private == CK_FALSE) {
                        //all certificates on this token are public objects
                        freeObjectSearchList(session);
                        return CKR_OK;
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_MODIFIABLE:
                debug(DEBUG_VERBOSE,"  CKA_MODIFIABLE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL mod = CK_FALSE;
                    memcpy(&mod, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(mod == CK_TRUE) {
                        //all objects on this token are read only
                        freeObjectSearchList(session);
                        return CKR_OK;
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_LABEL:
                debug(DEBUG_VERBOSE,"  CKA_LABEL\n");
                if (pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        char sn[pTemplate[i].ulValueLen];
                        
                        X509_NAME_oneline(cur->storage.certificate.x509->cert_info->subject, sn, pTemplate[i].ulValueLen);
                        
                        if(strncmp(sn, pTemplate[i].pValue, pTemplate[i].ulValueLen) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
                
            case CKA_CERTIFICATE_TYPE:
                debug(DEBUG_VERBOSE,"  CKA_CERTIFICATE_TYPE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_CERTIFICATE_TYPE certType = CKC_X_509;
                    memcpy(&certType, pTemplate[i].pValue, sizeof(CK_CERTIFICATE_TYPE));
                    if(certType != CKC_X_509) {
                        //all certs are X.509 certs
                        freeObjectSearchList(session);
                        return CKR_OK;
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_TRUSTED:
                debug(DEBUG_VERBOSE,"  CKA_TRUSTED\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL trusted = CK_FALSE;
                    objectEntry *cur = session->objectList;
                    memcpy(&trusted, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    while(cur != NULL) {
                        if(cur->storage.certificate.havePrivateKey) {
                            if(trusted == CK_TRUE) {
                                //keep this object
                                cur = cur->nextObject;
                            } else {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        } else {
                            if(trusted == CK_FALSE) {
                                //keep this object
                                cur = cur->nextObject;
                            } else {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_CERTIFICATE_CATEGORY:
                debug(DEBUG_VERBOSE,"  CKA_CERTIFICATE_CATEGORY\n");
                /* 0 = unspecified (default)
                 * 1 = token user (priv-key availible)
                 * 2 = CA cert
                 * 3 = other
                 */
                if (pTemplate[i].pValue != NULL) {
                    CK_ULONG certCat = 0;
                    objectEntry *cur = session->objectList;
                    memcpy(&certCat, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(certCat == 1) {
                        while(cur != NULL) {
                            if(cur->storage.certificate.havePrivateKey) {
                                //keep this object
                                cur = cur->nextObject;
                            } else {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_CHECK_VALUE:
                debug(DEBUG_VERBOSE,"  CKA_CHECK_VALUE\n");
                /* The value of this attribute is derived from the certificate by 
                 * taking the first three bytes of the SHA-1 hash of the certificate
                 * object’s CKA_VALUE attribute. 
                 *
                 * Since we use the SHA-1 of the certificate as the CKA_ID we already
                 * have the value and don't need to compute it again. 
                 */
                if (pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        if(memcmp(cur->storage.certificate.keyId, pTemplate[i].pValue, 3) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_START_DATE:
                debug(DEBUG_VERBOSE,"  CKA_START_DATE\n");
                //TODO (not often used)
                break;
                
            case CKA_END_DATE:
                debug(DEBUG_VERBOSE,"  CKA_END_DATE\n");
                //TODO (not often used)
                break;
                
            case CKA_SUBJECT:
                debug(DEBUG_VERBOSE,"  CKA_SUBJECT\n");
                /* DER-encoded certificate subject name */
                if(pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->subject, NULL);
                        if (pTemplate[i].ulValueLen < n) {
                            //too small to match
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                            
                        } else {
                            unsigned char *sn;
                            n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->subject, &sn);
                            if(memcmp(sn, pTemplate[i].pValue, n) != 0) {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_ID:
                debug(DEBUG_VERBOSE,"  CKA_ID\n");
                /* Key identifier for pub/pri keypair */
                if (pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen < SHA_DIGEST_LENGTH) {
                        //not long enough to match anything of ours
                        freeObjectSearchList(session);
                        break;
                    }
                    
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        if(memcmp(cur->storage.certificate.keyId, pTemplate[i].pValue, SHA_DIGEST_LENGTH) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_ISSUER:
                debug(DEBUG_VERBOSE,"  CKA_ISSUER\n");
                /* DER-encoded certificate issuer name */
                if(pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        debug(DEBUG_VERBOSE,"    Checking on object %d\n",cur->id);
                        n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->issuer, NULL);
                        if (pTemplate[i].ulValueLen < n) {
                            //too small to match
                            debug(DEBUG_VERBOSE,"    this cert's issuer size is %d and Templates size is %d. No match.\n",n,pTemplate[i].ulValueLen);
                            objectEntry *rem = cur;
                            removeObjectFromSearchResults(session, rem);                            
                        } else {
                            unsigned char *in,*inorig;
                            debug(DEBUG_VERBOSE, "    About to fetch issuers\n");
                            n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->issuer, NULL);
                            in = malloc(n);
                            inorig = in;
                            n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->issuer, &in);
                            in = inorig;
                            debug(DEBUG_VERBOSE, "    About to compare issuers\n");
                            if(memcmp(in, pTemplate[i].pValue, n) != 0) {
                                debug(DEBUG_VERBOSE,"    this cert's issuer did not match the Templates issuer.\n");
                                objectEntry *rem = cur; 
                                removeObjectFromSearchResults(session, rem); 
                            }
                            free(in);
                        }
                        cur = cur->nextObject;
                        debug(DEBUG_VERBOSE,"    Foo!\n");
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_SERIAL_NUMBER:
                debug(DEBUG_VERBOSE,"  CKA_SERIAL_NUMBER\n");
                /* DER-encoded certificate serial number */
                if(pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        n = i2d_ASN1_INTEGER(cur->storage.certificate.x509->cert_info->serialNumber, NULL);
                        if (pTemplate[i].ulValueLen < n) {
                            //too small to match
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        } else {
                            unsigned char *sn;
                            n = i2d_ASN1_INTEGER(cur->storage.certificate.x509->cert_info->serialNumber, &sn);
                            if(memcmp(sn, pTemplate[i].pValue, n) != 0) {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_VALUE:
                debug(DEBUG_VERBOSE,"  CKA_VALUE\n");
                //TODO Who searches for the exact value anyway?
                break;
                
                
            case CKA_URL:
                debug(DEBUG_VERBOSE,"  CKA_URL\n");
                //TODO
                break;
                
            case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
                debug(DEBUG_VERBOSE,"  CKA_HASH_OF_SUBJECT_PUBLIC_KEY\n");
                //TODO
                break;
                
            case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
                debug(DEBUG_VERBOSE,"  CKA_HASH_OF_ISSUER_PUBLIC_KEY\n");
                /* SHA-1 hash of the issuer public key */
                //TODO
                break;
                
            case CKA_JAVA_MIDP_SECURITY_DOMAIN:
                debug(DEBUG_VERBOSE,"  CKA_JAVA_MIDP_SECURITY_DOMAIN\n");
                /* Java MIDP security domain:
                 * 0 = unspecified
                 * 1 = manufacturer
                 * 2 = operator
                 * 3 = 3rd party
                 */
                //TODO
                break;
                
            default:
                debug(DEBUG_IMPORTANT,"Unknown CKO_CERTIFICATE attribute requested: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
                return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    session->cursor = session->searchList;
    return CKR_OK;
}

CK_RV
findObjectsInitPublicKey(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    objectEntry *object = NULL;
    CK_ULONG i = 0;
    int n = 0;
    
    
    debug(DEBUG_VERBOSE,"CKO_PUBLIC_KEY (0x%X)\n", CKO_PUBLIC_KEY);
    
    if(session->objectList == NULL) {
        session->searchList = NULL;
        session->cursor = NULL;
        return CKR_OK;
    }
    
    /* add all cert objects to search results, then remove based on tempalte */
    object = session->objectList;
    while(object != NULL) {
        if(object->class == CKO_PUBLIC_KEY) {
            addObjectToSearchResults(session,object);
        }
        object = object->nextObject;
    }
    
    if(session->objectList == NULL) {
        session->searchList = NULL;
        session->cursor = NULL;
        return CKR_OK;
    }
    
    for(i = 0; i < ulCount; i++) {
        switch(pTemplate[i].type) {
            case CKA_CLASS:
                //already handled
                break;
            case CKA_TOKEN:
                debug(DEBUG_VERBOSE,"  CKA_TOKEN\n");
                
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL token = CK_TRUE;
                    memcpy(&token, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(token == CK_FALSE) {
                        //all objects on this token are token objects
                        freeObjectSearchList(session);
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
                
            case CKA_PRIVATE:
                debug(DEBUG_VERBOSE,"  CKA_PRIVATE\n");
                
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL private = CK_TRUE;
                    memcpy(&private, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(private == CK_FALSE) {
                        //all private keys on this token are private objects
                        freeObjectSearchList(session);
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_MODIFIABLE:
                debug(DEBUG_VERBOSE,"  CKA_MODIFIABLE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL mod = CK_FALSE;
                    memcpy(&mod, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(mod == CK_TRUE) {
                        //all objects on this token are read only
                        freeObjectSearchList(session);
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_LABEL:
                debug(DEBUG_VERBOSE,"  CKA_LABEL\n");
                if (pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        char sn[pTemplate[i].ulValueLen+1];
                        
                        X509_NAME_oneline(cur->storage.publicKey.x509->cert_info->subject, sn, pTemplate[i].ulValueLen+1);
                        
                        if(strncmp(sn, pTemplate[i].pValue, pTemplate[i].ulValueLen) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_KEY_TYPE:
                debug(DEBUG_VERBOSE,"  CKA_KEY_TYPE\n");
                //TODO
                break;
                
            case CKA_ID:
                debug(DEBUG_VERBOSE,"  CKA_ID\n");
                /* Key identifier for pub/pri keypair */
                if (pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen < SHA_DIGEST_LENGTH) {
                        //not long enough to match anything of ours
                        freeObjectSearchList(session);
                        break;
                    }
                    
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        if(memcmp(cur->storage.certificate.keyId, pTemplate[i].pValue, SHA_DIGEST_LENGTH) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_START_DATE:
                debug(DEBUG_VERBOSE,"  CKA_START_DATE\n");
                //TODO
                break;
                
            case CKA_END_DATE:
                debug(DEBUG_VERBOSE,"  CKA_END_DATE\n");
                //TODO
                break;
                
            case CKA_DERIVE:
                debug(DEBUG_VERBOSE,"  CKA_DERIVE\n");
                //TODO
                break;
                
            case CKA_LOCAL:
                debug(DEBUG_VERBOSE,"  CKA_LOCAL\n");
                //TODO
                break;
                
            case CKA_KEY_GEN_MECHANISM:
                debug(DEBUG_VERBOSE,"  CKA_KEY_GEN_MECHANISM\n");
                //TODO
                break;
                
            case CKA_ALLOWED_MECHANISMS:
                debug(DEBUG_VERBOSE,"  CKA_ALLOWED_MECHANISMS\n");
                //TODO
                break;
                
            case CKA_SUBJECT:
                /* DER-encoded certificate subject name */
                debug(DEBUG_VERBOSE,"  CKA_SUBJECT\n");
                if(pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        n = i2d_X509_NAME(cur->storage.publicKey.x509->cert_info->subject, NULL);
                        if (pTemplate[i].ulValueLen < n) {
                            //too small to match
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                            
                        } else {
                            unsigned char *sn;
                            n = i2d_X509_NAME(cur->storage.publicKey.x509->cert_info->subject, &sn);
                            if(memcmp(sn, pTemplate[i].pValue, n) != 0) {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_ENCRYPT:
                debug(DEBUG_VERBOSE,"  CKA_ENCRYPT\n");
                //TODO
                break;
                
            case CKA_VERIFY:
                debug(DEBUG_VERBOSE,"  CKA_VERIFY\n");
                //TODO
                break;
                
            case CKA_VERIFY_RECOVER:
                debug(DEBUG_VERBOSE,"  CKA_VERIFY_RECOVER\n");
                //TODO
                break;
                
            case CKA_WRAP:
                debug(DEBUG_VERBOSE,"  CKA_WRAP\n");
                //TODO
                break;
                
            case CKA_TRUSTED:
                debug(DEBUG_VERBOSE,"  CKA_TRUSTED\n");
                //TODO
                break;
                
            case CKA_WRAP_TEMPLATE:
                debug(DEBUG_VERBOSE,"  CKA_WRAP_TEMPLATE\n");
                //TODO
                break;
                
            default:
                debug(DEBUG_IMPORTANT,"Unknown CKO_PRIVATE_KEY attribute requested: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
                return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    session->cursor = session->searchList;
    return CKR_OK;
}   

CK_RV
findObjectsInitPrivateKey(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    objectEntry *object = NULL;
    CK_ULONG i = 0;
    int n = 0;
    
    
    debug(DEBUG_VERBOSE,"CKO_PRIVATE_KEY (0x%X)\n", CKO_PRIVATE_KEY);
    
    if(session->objectList == NULL) {
        session->searchList = NULL;
        session->cursor = NULL;
        return CKR_OK;
    }
    
    /* add all cert objects to search results, then remove based on tempalte */
    object = session->objectList;
    while(object != NULL) {
        if(object->class == CKO_PRIVATE_KEY) {
            addObjectToSearchResults(session,object);
        }
        object = object->nextObject;
    }
    
    if(session->objectList == NULL) {
        session->searchList = NULL;
        session->cursor = NULL;
        return CKR_OK;
    }
    
    
    for(i = 0; i < ulCount; i++) {
        switch(pTemplate[i].type) {
            case CKA_CLASS:
                //already handled
                break;
            case CKA_TOKEN:
                debug(DEBUG_VERBOSE,"  CKA_TOKEN\n");
                
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL token = CK_TRUE;
                    memcpy(&token, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(token == CK_FALSE) {
                        //all objects on this token are token objects
                        freeObjectSearchList(session);
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
                
            case CKA_PRIVATE:
                debug(DEBUG_VERBOSE,"  CKA_PRIVATE\n");
                
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL private = CK_TRUE;
                    memcpy(&private, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(private == CK_FALSE) {
                        //all private keys on this token are private objects
                        freeObjectSearchList(session);
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_MODIFIABLE:
                debug(DEBUG_VERBOSE,"  CKA_MODIFIABLE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL mod = CK_FALSE;
                    memcpy(&mod, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                    if(mod == CK_TRUE) {
                        //all objects on this token are read only
                        freeObjectSearchList(session);
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_LABEL:
                debug(DEBUG_VERBOSE,"  CKA_LABEL\n");
                if (pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        char sn[pTemplate[i].ulValueLen];
                        
                        X509_NAME_oneline(cur->storage.privateKey.x509->cert_info->subject, sn, pTemplate[i].ulValueLen);
                        
                        if(strncmp(sn, pTemplate[i].pValue, pTemplate[i].ulValueLen) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_KEY_TYPE:
                debug(DEBUG_VERBOSE,"  CKA_KEY_TYPE\n");
                //TODO: do something useful with this
                switch(  *((CK_KEY_TYPE *) pTemplate[i].pValue) ) {
                    case CKK_RSA:
                        debug(DEBUG_VERBOSE,"     CKK_RSA\n");
                        break;
                    case CKK_DSA:
                        debug(DEBUG_VERBOSE,"     CKK_DSA\n");
                        break;
                    case CKK_DH:
                        debug(DEBUG_VERBOSE,"     CKK_DH\n");
                        break;
                    default:
                        debug(DEBUG_VERBOSE,"     0x%X\n",*((CK_KEY_TYPE *) pTemplate[i].pValue));
                        break;
                }
                break;
                
            case CKA_ID:
                debug(DEBUG_VERBOSE,"  CKA_ID\n");
                /* Key identifier for pub/pri keypair */
                if (pTemplate[i].pValue != NULL) {
                    debug(DEBUG_VERBOSE,"     %s\n",hexify(pTemplate[i].pValue, pTemplate[i].ulValueLen));
                    if(pTemplate[i].ulValueLen < SHA_DIGEST_LENGTH) {
                        //not long enough to match anything of ours
                        freeObjectSearchList(session);
                        break;
                    }
                    
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        if(memcmp(cur->storage.certificate.keyId, pTemplate[i].pValue, SHA_DIGEST_LENGTH) == 0) {
                            //keep this object
                            cur = cur->nextObject;
                        } else {
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_START_DATE:
                debug(DEBUG_VERBOSE,"  CKA_START_DATE\n");
                //TODO
                break;
                
            case CKA_END_DATE:
                debug(DEBUG_VERBOSE,"  CKA_END_DATE\n");
                //TODO
                break;
                
            case CKA_DERIVE:
                debug(DEBUG_VERBOSE,"  CKA_DERIVE\n");
                //TODO
                break;
                
            case CKA_LOCAL:
                debug(DEBUG_VERBOSE,"  CKA_LOCAL\n");
                //TODO
                break;
                
            case CKA_KEY_GEN_MECHANISM:
                debug(DEBUG_VERBOSE,"  CKA_KEY_GEN_MECHANISM\n");
                //TODO
                break;
                
            case CKA_ALLOWED_MECHANISMS:
                debug(DEBUG_VERBOSE,"  CKA_ALLOWED_MECHANISMS\n");
                //TODO
                break;
                
            case CKA_SUBJECT:
                /* DER-encoded certificate subject name */
                debug(DEBUG_VERBOSE,"  CKA_SUBJECT\n");
                if(pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->subject, NULL);
                        if (pTemplate[i].ulValueLen < n) {
                            //too small to match
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);
                            
                        } else {
                            unsigned char *sn;
                            n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->subject, &sn);
                            if(memcmp(sn, pTemplate[i].pValue, n) != 0) {
                                objectEntry *rem = cur;
                                cur = cur->nextObject;
                                removeObjectFromSearchResults(session, rem);
                            }
                        }
                    }
                } else {
                    return CKR_ARGUMENTS_BAD;
                }
                break;
                
            case CKA_SENSITIVE:
                debug(DEBUG_VERBOSE,"  CKA_SENSITIVE\n");
                //TODO
                break;
                
            case CKA_DECRYPT:
                debug(DEBUG_VERBOSE,"  CKA_DECRYPT\n");
                //TODO
                break;
                
            case CKA_SIGN:
                debug(DEBUG_VERBOSE,"  CKA_SIGN\n");
                //TODO
                break;
                
            case CKA_SIGN_RECOVER:
                debug(DEBUG_VERBOSE,"  CKA_SIGN_RECOVER\n");
                //TODO
                break;
                
            case CKA_UNWRAP:
                debug(DEBUG_VERBOSE,"  CKA_UNWRAP\n");
                //TODO
                break;
                
            case CKA_EXTRACTABLE:
                debug(DEBUG_VERBOSE,"  CKA_EXTRACTABLE\n");
                //TODO
                break;
                
            case CKA_ALWAYS_SENSITIVE:
                debug(DEBUG_VERBOSE,"  CKA_ALWAYS_SENSITIVE\n");
                //TODO
                break;
                
            case CKA_NEVER_EXTRACTABLE:
                debug(DEBUG_VERBOSE,"  CKA_NEVER_EXTRACTABLE\n");
                //TODO
                break;
                
            case CKA_WRAP_WITH_TRUSTED:
                debug(DEBUG_VERBOSE,"  CKA_WRAP_WITH_TRUSTED\n");
                //TODO
                break;
                
            case CKA_UNWRAP_TEMPLATE:
                debug(DEBUG_VERBOSE,"  CKA_UNWRAP_TEMPLATE\n");
                //TODO
                break;
                
            case CKA_ALWAYS_AUTHENTICATE:
                debug(DEBUG_VERBOSE,"  CKA_ALWAYS_AUTHENTICATE\n");
                //TODO
                break;
                
            default:
                debug(DEBUG_IMPORTANT,"Unknown CKO_PRIVATE_KEY attribute requested: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
                return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    
    session->cursor = session->searchList;
    return CKR_OK;
}    

void
setString(char *in, char *out, int len) 
{
    memset(out, ' ', len);
    memcpy(out, in, MIN(strlen(in),len) );
}

char * 
basename(const char *input) 
{
    const char *base;
    for(base = input; *input; input++) {
        if( (*input) == '/' ) {
            base = input + 1;
        }
    }
    return (char *) base;
}

void
setDateFromASN1Time(const ASN1_TIME *aTime, char *out) 
{
    int tmp = 0;
    
    if (aTime->type == V_ASN1_UTCTIME) {
        tmp = ((aTime->data[0] - '0') * 10) + (aTime->data[1] - '0');
        if (tmp < 50) {
            out[0] = '2';
            out[1] = '0';
        } else {
            out[0] = '1';
            out[1] = '2';
        }
        memcpy(&(out[2]), aTime->data, 6);
    } else {
        memcpy(out,aTime->data, 8);
    }
}

CSSM_ALGORITHMS
pMechanismToCSSM_ALGID(CK_MECHANISM_PTR pMechanism){
    switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			return CSSM_ALGID_RSA; 
		case CKM_MD2_RSA_PKCS:
			return CSSM_ALGID_MD2WithRSA;
		case CKM_MD5_RSA_PKCS:
			return CSSM_ALGID_MD5WithRSA; 
		case CKM_SHA1_RSA_PKCS:
			return CSSM_ALGID_SHA1WithRSA; 
		case CKM_DSA:
			return CSSM_ALGID_DSA; 
		case CKM_DSA_SHA1:
			return CSSM_ALGID_SHA1WithDSA; 
		case CKM_ECDSA:
			return CSSM_ALGID_ECDSA; 
		case CKM_ECDSA_SHA1:
			return CSSM_ALGID_SHA1WithECDSA; 
		case CKM_RC2_MAC:
			return CSSM_ALGID_RC2; 
		case CKM_RC5_MAC:
			return CSSM_ALGID_RC5; 
		case CKM_DES_MAC:
			return CSSM_ALGID_DES; 
		case CKM_DES3_MAC:
			return CSSM_ALGID_3DES; 
		case CKM_CAST_MAC:
			return CSSM_ALGID_CAST; 
		case CKM_CAST3_MAC:
			return CSSM_ALGID_CAST3; 
		case CKM_CAST5_MAC:
			return CSSM_ALGID_CAST5; 
		case CKM_IDEA_MAC:
			return CSSM_ALGID_IDEA; 
		case CKM_CDMF_MAC:
			return CSSM_ALGID_CDMF; 
		case CKM_MD2_HMAC:
			return CSSM_ALGID_MD2; 
		case CKM_MD5_HMAC:
			return CSSM_ALGID_MD5; 
		case CKM_SHA_1_HMAC:
			return CSSM_ALGID_SHA1; 
		case CKM_RIPEMD128_HMAC:
			return CSSM_ALGID_RIPEMAC; 
		case CKM_SSL3_MD5_MAC:
			return CSSM_ALGID_SSL3MD5_MAC;
		case CKM_SSL3_SHA1_MAC:
			return CSSM_ALGID_SSL3SHA1_MAC; 
            
			
			
            /* Supported by PKCS, but no equiv in CSSM */
		case CKM_RC2_MAC_GENERAL:
		case CKM_RC5_MAC_GENERAL:
		case CKM_AES_MAC_GENERAL:
		case CKM_AES_MAC:
		case CKM_DES_MAC_GENERAL:			
		case CKM_DES3_MAC_GENERAL:
		case CKM_CAST_MAC_GENERAL:	
		case CKM_CAST5_MAC_GENERAL:
		case CKM_IDEA_MAC_GENERAL:	
		case CKM_CDMF_MAC_GENERAL:
		case CKM_MD2_HMAC_GENERAL:
		case CKM_MD5_HMAC_GENERAL:
		case CKM_SHA_1_HMAC_GENERAL:
		case CKM_SHA256_HMAC_GENERAL:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC_GENERAL:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC_GENERAL:
		case CKM_SHA512_HMAC:
		case CKM_RIPEMD128_HMAC_GENERAL:
		case CKM_RIPEMD160_HMAC_GENERAL:
		case CKM_RIPEMD160_HMAC:
		case CKM_RSA_PKCS_PSS:			
		case CKM_RSA_9796:
		case CKM_RSA_X_509:
		case CKM_RSA_X9_31:					
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_RIPEMD128_RSA_PKCS:
		case CKM_RIPEMD160_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_X9_31:
		case CKM_FORTEZZA_TIMESTAMP:
		case CKM_CMS_SIG:
			
			return CKR_MECHANISM_PARAM_INVALID;
			
		default:
            debug(DEBUG_IMPORTANT,"Mechanism that we dont know how to handle (yet?) 0x%X (%s)\n",pMechanism->mechanism, getCKMName(pMechanism->mechanism));
			return CKR_MECHANISM_INVALID;
    }
}
