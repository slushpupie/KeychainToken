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
        debug(1, "%s: Failed to copy keychain search list\n", __FUNCTION__);
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
            if(useWhitelist()) {
                if(isKeychainWhitelisted(keychainName) || isKeychainGreylisted(keychainName)) {
                    keychainSlots[j++] = (SecKeychainRef) CFArrayGetValueAtIndex(array, i);
                }
            } else {
                if(!isKeychainBlacklisted(keychainName)) {
                    keychainSlots[j++] = (SecKeychainRef) CFArrayGetValueAtIndex(array,i);
                }
            }
            
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
    debug(1,"Adding object %u\n",object->id);
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
    
    debug(1,"Freeing all objects for session\n");
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
    debug(1," Deleting object %u\n",object->id);
    
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
                debug(1,"OpenSSL failed to parse certificate\n");
                free(object);
                return NULL;
            }
            object->storage.certificate.certRef = certRef;
            memcpy(object->storage.certificate.keyId,digest,SHA_DIGEST_LENGTH);
            CFRetain(object->storage.certificate.certRef);
            return object;
            
        case CKO_PUBLIC_KEY:
            
            
            status = SecCertificateCopyPublicKey(certRef, &(object->storage.publicKey.keyRef));
            memcpy(object->storage.publicKey.keyId,digest,SHA_DIGEST_LENGTH);
            if (status != 0) {
                free(object);
                return NULL;
            }
            
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
                debug(1,"OpenSSL failed to parse certificate\n");
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
            status = SecIdentityCopyPrivateKey(idRef, &(object->storage.privateKey.keyRef));
            if (status != 0) {
                free(object);
                return NULL;
            }
            debug(1,"*PrivateKey SecKeyRef=0x%X\n",object->storage.privateKey.keyRef);
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
    debug(1,"Requested object id %u\n",hObject);
    
    while(object != NULL) {
        if(object->id == hObject) {
            return object;
        }
        object = object->nextObject;
    }
    
    return NULL;
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
    CSSM_DATA certData;
    unsigned char *pData;
    OSStatus status = 0;
    int n = 0;
    
    SecCertificateGetData(object->storage.certificate.certRef, &certData);
    if (status != 0) {
        debug(1,"Error getting certificate data");
        return CKR_GENERAL_ERROR;
    }
    pData = certData.Data;
    
    debug(1,"Getting certificate attributes\n");
    for (i = 0 ; i < ulCount; i++) {
        switch (pTemplate[i].type) {
                
                
            case CKA_CLASS:
                debug(1,"  CKA_CLASS\n");
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(object->class)) {
                        memcpy(pTemplate[i].pValue, &object->class, sizeof(object->class));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(object->class);
                break;
                
            case CKA_TOKEN:
                debug(1,"  CKA_TOKEN\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL t = CK_TRUE;
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &t, sizeof(CK_BBOOL));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
                
            case CKA_PRIVATE:
                debug(1,"  CKA_PRIVATE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL f = CK_FALSE;
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
                
            case CKA_MODIFIABLE:
                debug(1,"  CKA_MODIFIABLE\n");
                if (pTemplate[i].pValue != NULL) {
                    CK_BBOOL f = CK_FALSE;
                    if (pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                        memcpy(pTemplate[i].pValue, &f, sizeof(CK_BBOOL));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                break;
                
            case CKA_LABEL:
                debug(1,"  CKA_LABEL\n");
            {
                
                char *sn = X509_NAME_oneline(object->storage.certificate.x509->cert_info->subject, NULL, 256);
                
                
                n = strlen(sn);
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n-1) {
                        memcpy(pTemplate[i].pValue, sn, n-1); /*not null terminated*/
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = n-1;
            }
                break;
                
                
                
            case CKA_CERTIFICATE_TYPE:
                debug(1,"  CKA_CERTIFICATE_TYPE\n");
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(CK_CERTIFICATE_TYPE)) {
                        CK_CERTIFICATE_TYPE certType = CKC_X_509;
                        memcpy(pTemplate[i].pValue, &certType, sizeof(CK_CERTIFICATE_TYPE));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
                break;
                
            case CKA_TRUSTED:
                debug(1,"  CKA_TRUSTED\n");
                if(object->storage.certificate.havePrivateKey) {
                    if(pTemplate[i].pValue != NULL) {
                        if(pTemplate[i].ulValueLen >= sizeof(CK_BBOOL)) {
                            CK_BBOOL trusted = CK_TRUE;
                            memcpy(pTemplate[i].pValue, &trusted, sizeof(CK_BBOOL));
                        } else {
                            return CKR_BUFFER_TOO_SMALL;
                        }
                    }
                    pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                }
                
                break;
                
            case CKA_CERTIFICATE_CATEGORY:
                debug(1,"  CKA_CERTIFICATE_CATEGORY\n");
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
                        } else {
                            return CKR_BUFFER_TOO_SMALL;
                        }
                    }
                    pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                }
                break;
                
            case CKA_CHECK_VALUE:
                debug(1,"  CKA_CHECK_VALUE\n");
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
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = 3;
                break;
                
            case CKA_START_DATE:
                debug(1,"  CKA_START_DATE\n");
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= 8) {
                        setDateFromASN1Time(object->storage.certificate.x509->cert_info->validity->notBefore, pTemplate[i].pValue);
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = 8;
                break;
                
            case CKA_END_DATE:
                debug(1,"  CKA_END_DATE\n");
                if(pTemplate[i].pValue != NULL) {
                    if(pTemplate[i].ulValueLen >= 8) {
                        setDateFromASN1Time(object->storage.certificate.x509->cert_info->validity->notAfter, pTemplate[i].pValue);
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = 8;
                break;
                
            case CKA_SUBJECT:
                debug(1,"  CKA_SUBJECT\n");
                /* DER-encoded certificate subject name */
                n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->subject, NULL);
                
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->subject, (unsigned char **) &(pTemplate[i].pValue));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = n;
                
                break;
                
            case CKA_ID:
                debug(1,"  CKA_ID\n");
                /* Key identifier for pub/pri keypair */
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= SHA_DIGEST_LENGTH) {
                        debug(1,"     %s\n",hexify(object->storage.certificate.keyId, SHA_DIGEST_LENGTH));
                        memcpy(pTemplate[i].pValue, &object->storage.certificate.keyId, SHA_DIGEST_LENGTH);
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = SHA_DIGEST_LENGTH;
                
                break;
                
            case CKA_ISSUER:
                debug(1,"  CKA_ISSUER\n");
                /* DER-encoded certificate issuer name */
                n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->issuer, NULL);
                
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        n = i2d_X509_NAME(object->storage.certificate.x509->cert_info->issuer, (unsigned char **) &(pTemplate[i].pValue));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = n;
                
                break;
                
            case CKA_SERIAL_NUMBER:
                debug(1,"  CKA_SERIAL_NUMBER\n");
                /* DER-encoded certificate serial number */
                n = i2d_ASN1_INTEGER(object->storage.certificate.x509->cert_info->serialNumber, NULL);
                
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= n) {
                        n = i2d_ASN1_INTEGER(object->storage.certificate.x509->cert_info->serialNumber, (unsigned char **) &(pTemplate[i].pValue));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = n;
                
                break;
                
            case CKA_VALUE:
                debug(1,"  CKA_VALUE\n");
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= certData.Length) {
                        memcpy(pTemplate[i].pValue, certData.Data, certData.Length);
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = certData.Length;
                
                break;
                
                
            case CKA_URL:
                debug(1,"  CKA_URL\n");
                /* RFC2279 string of the URL where certificate can be obtained */
                if (object->class != CKO_CERTIFICATE) {
                    return CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
                debug(1,"  CKA_HASH_OF_SUBJECT_PUBLIC_KEY\n");
                /* SHA-1 hash of the subject public key */
                if (object->class != CKO_CERTIFICATE) {
                    return CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
                debug(1,"  CKA_HASH_OF_ISSUER_PUBLIC_KEY\n");
                /* SHA-1 hash of the issuer public key */
                if (object->class != CKO_CERTIFICATE) {
                    return CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            case CKA_JAVA_MIDP_SECURITY_DOMAIN:
                debug(1,"  CKA_JAVA_MIDP_SECURITY_DOMAIN\n");
                /* Java MIDP security domain:
                 * 0 = unspecified
                 * 1 = manufacturer
                 * 2 = operator
                 * 3 = 3rd party
                 */
                if (object->class != CKO_CERTIFICATE) {
                    return CKR_ATTRIBUTE_TYPE_INVALID;
                }
                
            default:
                debug(1,"Unknown CKO_CERTIFICATE attribute requested: 0x%X\n", pTemplate[i].type);
                return CKR_ATTRIBUTE_TYPE_INVALID;
                
        }
    }
    return CKR_OK;
}

CK_RV
getAttributeValuePublicKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i = 0;
    
    for (i = 0 ; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(object->class)) {
                        memcpy(pTemplate[i].pValue, &object->class, sizeof(object->class));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                break;
            }   
            case CKA_ID:
                /* Key identifier for key */
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= SHA_DIGEST_LENGTH) {
                        debug(1,"     %s\n",hexify(object->storage.publicKey.keyId, SHA_DIGEST_LENGTH));
                        memcpy(pTemplate[i].pValue, &object->storage.publicKey.keyId, SHA_DIGEST_LENGTH);
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
            default:
                debug(1,"Unknown CKO_PUBLIC_KEY attribute requested: 0x%X\n", pTemplate[i].type);
                return CKR_ATTRIBUTE_TYPE_INVALID;
                
                
        }
    }
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

CK_RV
getAttributeValuePrivateKey(objectEntry *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
    CK_ULONG i = 0;
    
    for (i = 0 ; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_CLASS:
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= sizeof(object->class)) {
                        memcpy(pTemplate[i].pValue, &object->class, sizeof(object->class));
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
                    }
                }
                pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
                break;
            }   
            case CKA_ID:
                /* Key identifier for key */
                if (pTemplate[i].pValue != NULL) {
                    if (pTemplate[i].ulValueLen >= SHA_DIGEST_LENGTH) {
                        debug(1,"     %s\n",hexify(object->storage.privateKey.keyId, SHA_DIGEST_LENGTH));
                        memcpy(pTemplate[i].pValue, &object->storage.privateKey.keyId, SHA_DIGEST_LENGTH);
                    } else {
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
                        return CKR_BUFFER_TOO_SMALL;
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
                
            default:
                debug(1,"Unknown CKO_PUBLIC_KEY attribute requested: 0x%X\n", pTemplate[i].type);
                return CKR_ATTRIBUTE_TYPE_INVALID;
                
        }
    }
    return CKR_OK;
}

CK_RV
findObjectsInitCertificate(sessionEntry *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    objectEntry *object = NULL;
    CK_ULONG i = 0;
    int n = 0;
    
    debug(1,"CKO_CERTIFICATE (0x%X)\n", CKO_CERTIFICATE);
    
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
                debug(1,"  CKA_TOKEN\n");
                
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
                debug(1,"  CKA_PRIVATE\n");
                
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
                debug(1,"  CKA_MODIFIABLE\n");
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
                debug(1,"  CKA_LABEL\n");
                if (pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        char sn[pTemplate[i].ulValueLen+1];
                        
                        X509_NAME_oneline(cur->storage.certificate.x509->cert_info->subject, sn, pTemplate[i].ulValueLen+1);
                        
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
                debug(1,"  CKA_CERTIFICATE_TYPE\n");
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
                debug(1,"  CKA_TRUSTED\n");
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
                debug(1,"  CKA_CERTIFICATE_CATEGORY\n");
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
                debug(1,"  CKA_CHECK_VALUE\n");
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
                debug(1,"  CKA_START_DATE\n");
                //TODO (not often used)
                break;
                
            case CKA_END_DATE:
                debug(1,"  CKA_END_DATE\n");
                //TODO (not often used)
                break;
                
            case CKA_SUBJECT:
                debug(1,"  CKA_SUBJECT\n");
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
                debug(1,"  CKA_ID\n");
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
                debug(1,"  CKA_ISSUER\n");
                /* DER-encoded certificate issuer name */
                if(pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->issuer, NULL);
                        if (pTemplate[i].ulValueLen < n) {
                            //too small to match
                            objectEntry *rem = cur;
                            cur = cur->nextObject;
                            removeObjectFromSearchResults(session, rem);                            
                        } else {
                            unsigned char *in;
                            n = i2d_X509_NAME(cur->storage.certificate.x509->cert_info->issuer, &in);
                            if(memcmp(in, pTemplate[i].pValue, n) != 0) {
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
                
            case CKA_SERIAL_NUMBER:
                debug(1,"  CKA_SERIAL_NUMBER\n");
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
                debug(1,"  CKA_VALUE\n");
                //TODO Who searches for the exact value anyway?
                break;
                
                
            case CKA_URL:
                debug(1,"  CKA_URL\n");
                //TODO
                break;
                
            case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
                debug(1,"  CKA_HASH_OF_SUBJECT_PUBLIC_KEY\n");
                //TODO
                break;
                
            case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
                debug(1,"  CKA_HASH_OF_ISSUER_PUBLIC_KEY\n");
                /* SHA-1 hash of the issuer public key */
                //TODO
                break;
                
            case CKA_JAVA_MIDP_SECURITY_DOMAIN:
                debug(1,"  CKA_JAVA_MIDP_SECURITY_DOMAIN\n");
                /* Java MIDP security domain:
                 * 0 = unspecified
                 * 1 = manufacturer
                 * 2 = operator
                 * 3 = 3rd party
                 */
                //TODO
                break;
                
            default:
                debug(1,"Unknown CKO_CERTIFICATE attribute requested: 0x%X\n", pTemplate[i].type);
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
    
    
    debug(1,"CKO_PUBLIC_KEY (0x%X)\n", CKO_PUBLIC_KEY);
    
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
                debug(1,"  CKA_TOKEN\n");
                
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
                debug(1,"  CKA_PRIVATE\n");
                
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
                debug(1,"  CKA_MODIFIABLE\n");
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
                debug(1,"  CKA_LABEL\n");
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
                debug(1,"  CKA_KEY_TYPE\n");
                //TODO
                break;
                
            case CKA_ID:
                debug(1,"  CKA_ID\n");
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
                debug(1,"  CKA_START_DATE\n");
                //TODO
                break;
                
            case CKA_END_DATE:
                debug(1,"  CKA_END_DATE\n");
                //TODO
                break;
                
            case CKA_DERIVE:
                debug(1,"  CKA_DERIVE\n");
                //TODO
                break;
                
            case CKA_LOCAL:
                debug(1,"  CKA_LOCAL\n");
                //TODO
                break;
                
            case CKA_KEY_GEN_MECHANISM:
                debug(1,"  CKA_KEY_GEN_MECHANISM\n");
                //TODO
                break;
                
            case CKA_ALLOWED_MECHANISMS:
                debug(1,"  CKA_ALLOWED_MECHANISMS\n");
                //TODO
                break;
                
            case CKA_SUBJECT:
                /* DER-encoded certificate subject name */
                debug(1,"  CKA_SUBJECT\n");
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
                debug(1,"  CKA_ENCRYPT\n");
                //TODO
                break;
                
            case CKA_VERIFY:
                debug(1,"  CKA_VERIFY\n");
                //TODO
                break;
                
            case CKA_VERIFY_RECOVER:
                debug(1,"  CKA_VERIFY_RECOVER\n");
                //TODO
                break;
                
            case CKA_WRAP:
                debug(1,"  CKA_WRAP\n");
                //TODO
                break;
                
            case CKA_TRUSTED:
                debug(1,"  CKA_TRUSTED\n");
                //TODO
                break;
                
            case CKA_WRAP_TEMPLATE:
                debug(1,"  CKA_WRAP_TEMPLATE\n");
                //TODO
                break;
                
            default:
                debug(1,"Unknown CKO_PRIVATE_KEY attribute requested: 0x%X\n", pTemplate[i].type);
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
    
    
    debug(1,"CKO_PRIVATE_KEY (0x%X)\n", CKO_PRIVATE_KEY);
    
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
                debug(1,"  CKA_TOKEN\n");
                
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
                debug(1,"  CKA_PRIVATE\n");
                
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
                debug(1,"  CKA_MODIFIABLE\n");
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
                debug(1,"  CKA_LABEL\n");
                if (pTemplate[i].pValue != NULL) {
                    objectEntry *cur = session->objectList;
                    while(cur != NULL) {
                        char sn[pTemplate[i].ulValueLen+1];
                        
                        X509_NAME_oneline(cur->storage.privateKey.x509->cert_info->subject, sn, pTemplate[i].ulValueLen+1);
                        
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
                debug(1,"  CKA_KEY_TYPE\n");
                //TODO: do something useful with this
                switch(  *((CK_KEY_TYPE *) pTemplate[i].pValue) ) {
                    case CKK_RSA:
                        debug(1,"     CKK_RSA\n");
                        break;
                    case CKK_DSA:
                        debug(1,"     CKK_DSA\n");
                        break;
                    case CKK_DH:
                        debug(1,"     CKK_DH\n");
                        break;
                    default:
                        debug(1,"     0x%X\n",*((CK_KEY_TYPE *) pTemplate[i].pValue));
                        break;
                }
                break;
                
            case CKA_ID:
                debug(1,"  CKA_ID\n");
                /* Key identifier for pub/pri keypair */
                if (pTemplate[i].pValue != NULL) {
                    debug(1,"     %s\n",hexify(pTemplate[i].pValue, pTemplate[i].ulValueLen));
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
                debug(1,"  CKA_START_DATE\n");
                //TODO
                break;
                
            case CKA_END_DATE:
                debug(1,"  CKA_END_DATE\n");
                //TODO
                break;
                
            case CKA_DERIVE:
                debug(1,"  CKA_DERIVE\n");
                //TODO
                break;
                
            case CKA_LOCAL:
                debug(1,"  CKA_LOCAL\n");
                //TODO
                break;
                
            case CKA_KEY_GEN_MECHANISM:
                debug(1,"  CKA_KEY_GEN_MECHANISM\n");
                //TODO
                break;
                
            case CKA_ALLOWED_MECHANISMS:
                debug(1,"  CKA_ALLOWED_MECHANISMS\n");
                //TODO
                break;
                
            case CKA_SUBJECT:
                /* DER-encoded certificate subject name */
                debug(1,"  CKA_SUBJECT\n");
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
                debug(1,"  CKA_SENSITIVE\n");
                //TODO
                break;
                
            case CKA_DECRYPT:
                debug(1,"  CKA_DECRYPT\n");
                //TODO
                break;
                
            case CKA_SIGN:
                debug(1,"  CKA_SIGN\n");
                //TODO
                break;
                
            case CKA_SIGN_RECOVER:
                debug(1,"  CKA_SIGN_RECOVER\n");
                //TODO
                break;
                
            case CKA_UNWRAP:
                debug(1,"  CKA_UNWRAP\n");
                //TODO
                break;
                
            case CKA_EXTRACTABLE:
                debug(1,"  CKA_EXTRACTABLE\n");
                //TODO
                break;
                
            case CKA_ALWAYS_SENSITIVE:
                debug(1,"  CKA_ALWAYS_SENSITIVE\n");
                //TODO
                break;
                
            case CKA_NEVER_EXTRACTABLE:
                debug(1,"  CKA_NEVER_EXTRACTABLE\n");
                //TODO
                break;
                
            case CKA_WRAP_WITH_TRUSTED:
                debug(1,"  CKA_WRAP_WITH_TRUSTED\n");
                //TODO
                break;
                
            case CKA_UNWRAP_TEMPLATE:
                debug(1,"  CKA_UNWRAP_TEMPLATE\n");
                //TODO
                break;
                
            case CKA_ALWAYS_AUTHENTICATE:
                debug(1,"  CKA_ALWAYS_AUTHENTICATE\n");
                //TODO
                break;
                
            default:
                debug(1,"Unknown CKO_PRIVATE_KEY attribute requested: 0x%X\n", pTemplate[i].type);
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
