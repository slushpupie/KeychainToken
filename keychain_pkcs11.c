/*
 *  keychain_pkcs11.c
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/22/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#include "keychain_pkcs11.h"

#define CHECK_SLOTID(id) if ( ((id) < 0) || ((id) > MAX_SLOTS - 1) ) return CKR_SLOT_ID_INVALID

CK_RV
initialize(CK_VOID_PTR pInitArgs)
{
    CK_C_INITIALIZE_ARGS* initArgs = (CK_C_INITIALIZE_ARGS*) pInitArgs;
    CSSM_VERSION cmVersion;
    CSSM_GUID cmGUID;
    CSSM_PVC_MODE cmPvcPolicy;
    CSSM_RETURN ret;
    
    if ( initialized ) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    
    if (initArgs != NULL) {
        if (initArgs->flags & CKF_OS_LOCKING_OK) {
            debug(DEBUG_VERBOSE," CKF_OS_LOCKING_OK set\n");
            
        } else if(initArgs->flags * CKF_LIBRARY_CANT_CREATE_OS_THREADS) {
            debug(DEBUG_VERBOSE, " CKF_LIBRARY_CANT_CREATE_OS_THREADS set\n");
            /* No impact on us */
        }
        
        if(initArgs->flags & CKF_OS_LOCKING_OK) {
            if(initArgs->CreateMutex == NULL ||
               initArgs->DestroyMutex == NULL ||
               initArgs->LockMutex == NULL ||
               initArgs->UnlockMutex == NULL) {
                
                return CKR_CANT_LOCK;
            }
        }
        if(initArgs->CreateMutex != NULL ||
           initArgs->DestroyMutex != NULL ||
           initArgs->LockMutex != NULL ||
           initArgs->UnlockMutex != NULL) {
            mutex.use = true;
            mutex.CreateMutex = initArgs->CreateMutex;
            mutex.DestroyMutex = initArgs->DestroyMutex;
            mutex.LockMutex = initArgs->LockMutex;
            mutex.UnlockMutex = initArgs->UnlockMutex;
            
            mutex.CreateMutex( &(mutex.slotMutex) );
            mutex.CreateMutex( &(mutex.sessionMutex) );
            
        } else {
            mutex.use = false;
        }
        
        if(initArgs->pReserved != NULL) {
            return CKR_ARGUMENTS_BAD;
        }
        
        
        
        
        cmPvcPolicy = CSSM_PVC_NONE;
        cmVersion.Major = 2;
        cmVersion.Minor = 0;
        
        ret = CSSM_Init(&cmVersion, CSSM_PRIVILEGE_SCOPE_PROCESS, &cmGUID, CSSM_KEY_HIERARCHY_NONE, &cmPvcPolicy, (const void *)NULL);
        if (ret != 0) {
            cssmPerror("CSSM_Init", ret);
            return CKR_GENERAL_ERROR;
        }
        
        
    }
    initialized = TRUE;
    
    return CKR_OK;
}

CK_RV
finalize(CK_VOID_PTR pReserved)
{
    sessionEntry *cur, *next;
    
    cur = firstSession;
    if(cur != NULL) {
        next = firstSession->nextSession;
        while(next != NULL) {
            free(cur);
            cur = next;
            next = cur->nextSession;
        }
        free(cur);
    }
    
    if(mutex.use) {
        mutex.DestroyMutex( mutex.slotMutex );
    }
    
    CSSM_Terminate();
    initialized = false;
    
    return CKR_OK;
}

CK_RV
getInfo(CK_INFO_PTR p)
{
    ckInfo.manufacturerID[31] = ' ';
    ckInfo.libraryDescription[31] = ' ';
    *p = ckInfo;
    return CKR_OK;
}

CK_RV
getSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    unsigned int i,j;
    unsigned int numSlots;
    
    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if(mutex.use) {
        mutex.LockMutex(mutex.slotMutex);
    }
    numSlots = updateSlotList();
    
    
    debug(DEBUG_INFO,"Requested slots TP=%s numSlots=%d\n",(tokenPresent ? "true" : "false"), numSlots);
    if (pSlotList != NULL) {
        if(tokenPresent) {
            for(i=0,j=0; i < MAX_SLOTS; i++) {
                if(keychainSlots[i] != NULL) {
                    pSlotList[j++] = i;
                    debug(DEBUG_INFO,"slot[%d] = %d\n",j-1,i);
                }
            }
        } else {
            for(i=0; i < MAX_SLOTS; i++) {
                pSlotList[i] = i;
                debug(DEBUG_INFO,"slot[%d] = %d\n",i,i);
            }
        }
    }
    if (!tokenPresent) {
        *pulCount = MAX_SLOTS;
    } else {
        *pulCount = numSlots;
    }
    
    if(mutex.use) {
        mutex.UnlockMutex(mutex.slotMutex);
    }
    
    return CKR_OK;
}

CK_RV
getSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pSlotInfo) 
{
    
    if (pSlotInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    CHECK_SLOTID(slotID);
    
    pSlotInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    if (keychainSlots[slotID] != NULL) {
        char *keychainName;
        char *filename = NULL;
        OSStatus status = 0;
        UInt32 len = 0;
        
        pSlotInfo->flags |= CKF_TOKEN_PRESENT;
        
        keychainName = malloc(MAX_KEYCHAIN_PATH_LEN);
        memset(keychainName, 0, sizeof(keychainName));
        len = MAX_KEYCHAIN_PATH_LEN - 1;
        status = SecKeychainGetPath(keychainSlots[slotID], &len, keychainName);
        if (status != 0) {
            if(status == errSecBufferTooSmall) {
                debug(DEBUG_INFO,"Buffer of %d too small. Growing to %d\n", MAX_KEYCHAIN_PATH_LEN, len);
                free(keychainName);
                keychainName = malloc(len);
                status = SecKeychainGetPath(keychainSlots[slotID], &len, keychainName);
                if(status != 0) {
                    memcpy(keychainName, "keychain error", 15); 
                    debug(DEBUG_INFO,"Error getting keychain path: %d\n",status);
                }
            } 
        }
        
        filename = basename(keychainName);
        setString(filename, (char *)pSlotInfo->slotDescription, 64);
        
        
    } else {
        setString("Empty keychain slot", (char *)pSlotInfo->slotDescription, 64);
    }
    setString("Apple", (char *)pSlotInfo->manufacturerID, 32);
    pSlotInfo->hardwareVersion.major = 0;
    pSlotInfo->hardwareVersion.minor = 0;
    pSlotInfo->firmwareVersion.major = 0;
    pSlotInfo->firmwareVersion.minor = 0;
    
    return CKR_OK;
}

CK_RV
getTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pTokenInfo)
{
    OSStatus status;
    UInt32 vers = 0;
    char keychainName[MAX_KEYCHAIN_PATH_LEN];
    char *filename;
    UInt32 keychainLen = sizeof(keychainName) - 1; 
    
    
    
    if( ! initialized ) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    
    if (pTokenInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    CHECK_SLOTID(slotID);
    
    if (keychainSlots[slotID] != NULL) {
        
        
        memset(keychainName, 0, sizeof(keychainName));
        status = SecKeychainGetPath(keychainSlots[slotID], &keychainLen, keychainName);
        if (status != 0) {
            return CKR_GENERAL_ERROR;
        }
        
        filename = basename(keychainName);
        
        setString(filename, (char *)pTokenInfo->label, 32);
        setString("Apple Computer", (char *)pTokenInfo->manufacturerID, 32);
        setString("Keychain", (char *)pTokenInfo->model, 16);
        setString(filename,  (char *)pTokenInfo->serialNumber, 16);
        pTokenInfo->flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH; 
        
        if(isKeychainGreylisted(keychainName)) {
            pTokenInfo->flags |= CKF_USER_PIN_LOCKED | CKF_SO_PIN_LOCKED;
        } else { 
            pTokenInfo->flags |= CKF_LOGIN_REQUIRED;
        }
        
        pTokenInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
        pTokenInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
        pTokenInfo->ulMaxRwSessionCount = 0;
        pTokenInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
        pTokenInfo->ulMaxPinLen = 32;
        pTokenInfo->ulMinPinLen = 0;
        pTokenInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        pTokenInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        pTokenInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        pTokenInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        pTokenInfo->hardwareVersion.major = 0;
        pTokenInfo->hardwareVersion.minor = 0;
        
        status = SecKeychainGetVersion(&vers);
        if(status != 0) {
            /* not fatal */
            vers = 0;
        }
        
        pTokenInfo->firmwareVersion.major = vers;
        
        pTokenInfo->firmwareVersion.minor = 0;
        
        setString("1970010100000000" , (char *)pTokenInfo->utcTime, 16);
        
        return CKR_OK;
    } 
    return CKR_DEVICE_REMOVED;
}

CK_RV
waitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) 
{
    /* Since these are not tokens in the traditional sense, they cannot be inserted/removed
     * from a slot.  Thus, if CKF_DONT_BLOCK is called, all we do is return. Otherwise, 
     * We are supposed to wait for a token insert/removal event that will never happen; so
     * we essentially block forever. :-(
     */
    if(flags & CKF_DONT_BLOCK) {
        return CKR_NO_EVENT; 
    } else {
        /* while(initialized) { sleep(1000); } */
        return CKR_NO_EVENT;
    }
    
    debug(DEBUG_CRITICAL,"function not implemented\n");
    return CKR_GENERAL_ERROR;
}

CK_RV
getMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    unsigned long i;
    
    if(pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    CHECK_SLOTID(slotID);
    
    if(keychainSlots[slotID] == NULL) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    if(pMechanismList != NULL) {
        if (*pulCount < numMechanisms ) {
            *pulCount = numMechanisms;
            return CKR_BUFFER_TOO_SMALL;
        }
        for(i = 0; i < numMechanisms; i++) {
            pMechanismList[i] = mechanismList[i].mech;
        }
    }
    *pulCount = numMechanisms;
    
    return CKR_OK;
}

CK_RV
getMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) 
{
    unsigned long i;
    
    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    CHECK_SLOTID(slotID);
    
    if(keychainSlots[slotID] == NULL) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    
    for(i = 0; i < numMechanisms; i++) {
        if (mechanismList[i].mech == type) {
            *pInfo = mechanismList[i].info;
        }
        return CKR_OK;
    }
    return CKR_MECHANISM_INVALID;
}

CK_RV
openSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) 
{
    sessionEntry *newSession = NULL;
    sessionEntry *oldSession = NULL;
    CK_RV rv = CKR_OK;
    
    CHECK_SLOTID(slotID);
    
    if (phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (keychainSlots[slotID] == NULL) {
        return CKR_DEVICE_REMOVED;
    }
    
    if(mutex.use) {
        debug(DEBUG_INFO,"Locking sessionMutex\n");
        rv = mutex.LockMutex(mutex.sessionMutex);
        if(rv != CKR_OK) {
            return rv;
        }
    }
    newSession = malloc(sizeof(sessionEntry));
    if(newSession == NULL) {
        return CKR_HOST_MEMORY;
    }
    memset(newSession, 0, sizeof(sessionEntry));
    
    do {
        *phSession = ++sessionCounter;
        debug(DEBUG_INFO, "new session handle: %d\n", *phSession);
        oldSession = findSessionEntry(*phSession);
        if(oldSession != NULL) 
            debug(DEBUG_INFO, "oldSession with that handle found, trying again.");
    } while (oldSession != NULL);
    
    
    newSession->id = *phSession;
    newSession->flags = flags;
    newSession->state = CKS_RO_PUBLIC_SESSION;
    newSession->slot = slotID;
    newSession->objectCounter = 1;
    
    if(mutex.use) {
        rv = mutex.CreateMutex(&(newSession->myMutex));
        if(rv != CKR_OK) {
            debug(DEBUG_INFO, "unable to create a mutex for this session object\n");
            debug(DEBUG_INFO, "Unlocking sessionMutex\n");
            mutex.UnlockMutex(mutex.sessionMutex);
            return rv;
        }
    }
    
    addSession(newSession);
    
    if(mutex.use) {
        debug(DEBUG_INFO,"Unlocking sessionMutex\n");
        mutex.UnlockMutex(mutex.sessionMutex);
    }
    return CKR_OK;
}

CK_RV
closeSession(CK_SESSION_HANDLE hSession)
{
    if(mutex.use) {
        debug(DEBUG_INFO,"Locking sessionMutex\n");
        mutex.LockMutex(mutex.sessionMutex);
    }
    
    debug(DEBUG_INFO,"Closing session %d\n",hSession);
    removeSession(hSession);
    
    if(mutex.use) {
        debug(DEBUG_INFO,"Unlocking sessionMutex\n");
        mutex.UnlockMutex(mutex.sessionMutex);
    }
    
    return CKR_OK;
}

CK_RV
closeAllSessions(CK_SLOT_ID slotID) 
{    
    sessionEntry *cur, *next;
    
    CHECK_SLOTID(slotID);
    
    if(mutex.use) {
        debug(DEBUG_INFO,"Locking sessionMutex\n");
        mutex.LockMutex(mutex.sessionMutex);
    }
    
    cur = firstSession;
    if(cur != NULL) {
        next = firstSession->nextSession;
        while(next != NULL) {
            if(cur->slot == slotID)
                removeSession(cur->id);
            
            cur = next;
            next = cur->nextSession;
        }
        if(cur->slot == slotID)
            removeSession(cur->id);
    }
    
    if(mutex.use) {
        debug(DEBUG_INFO,"Unlocking sessionMutex\n");
        mutex.UnlockMutex(mutex.sessionMutex);
    }
    return CKR_OK;
}

CK_RV
getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) 
{
    sessionEntry *session;
    
    if(pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        debug(DEBUG_INFO,"session %d dosnt exist\n",hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    pInfo->slotID = session->slot;
    pInfo->state  = session->state;
    pInfo->flags  = session->flags;
    pInfo->ulDeviceError = 0;
    
    return CKR_OK;
}

CK_RV
login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) 
{
    OSStatus status = 0;
    sessionEntry *session;
    char keychainName[MAX_KEYCHAIN_PATH_LEN];
    UInt32 keychainLen = sizeof(keychainName) - 1;
    
    if (userType != CKU_USER) {
        return CKR_USER_TYPE_INVALID;
    }
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(mutex.use) {
        mutex.LockMutex(session->myMutex);
    }
    
    memset(keychainName, 0, sizeof(keychainName));
    status = SecKeychainGetPath(keychainSlots[session->slot], &keychainLen, keychainName);
    if (status != 0) {
        return CKR_GENERAL_ERROR;
    }
    
    if(isKeychainGreylisted(keychainName)) {
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }    
        return CKR_PIN_LOCKED;
    }
    
    status = SecKeychainUnlock(keychainSlots[ session->slot] , 0, NULL, FALSE);
    if (status != 0) {
        
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        
        if(status == errSecAuthFailed) 
            return CKR_PIN_INCORRECT;
        else if(status == errSecNoSuchKeychain) 
            return CKR_TOKEN_NOT_PRESENT;
        else if(status == errSecNoAccessForItem)
            return CKR_PIN_LOCKED;
        else 
            return CKR_GENERAL_ERROR;
    }
    
    session->loggedIn = TRUE;
    session->state = CKS_RO_USER_FUNCTIONS;
    
    if(mutex.use) {
        mutex.UnlockMutex(session->myMutex);
    }
    return CKR_OK;
}

CK_RV
logout(CK_SESSION_HANDLE hSession) 
{
    sessionEntry *session;
    OSStatus status;
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(mutex.use) {
        mutex.LockMutex(session->myMutex);
    }
    status = SecKeychainLock( keychainSlots[ session->slot ] );
    if (status != 0) {
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        return CKR_GENERAL_ERROR;
    }
    session->loggedIn = FALSE;
    session->state = CKS_RO_PUBLIC_SESSION;
    
    if(mutex.use) {
        mutex.UnlockMutex(session->myMutex);
    }
    return CKR_OK;
}

CK_RV
getAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    sessionEntry *session = NULL;
    objectEntry *object = NULL;
    
    if (pTemplate == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (ulCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    object = getObject(session, hObject);
    if(object == NULL) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    switch(object->class) {
        case CKO_CERTIFICATE:
            return getAttributeValueCertificate(object, pTemplate, ulCount);
        case CKO_PUBLIC_KEY:
            return getAttributeValuePublicKey(object, pTemplate, ulCount);
        case CKO_PRIVATE_KEY:
            return getAttributeValuePrivateKey(object, pTemplate, ulCount);
        default:
            debug(DEBUG_WARNING,"This object class is %s\n",getCKOName(object->class));
            /* This should never happen, since we dont create objects besides what
             * we know how to handle.
             */
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

CK_RV
findObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
    
    
    sessionEntry *session;
    OSStatus status;
    CK_ULONG i;
    objectEntry *object;
    
    SecKeychainSearchRef kcSearchReference = NULL;
    SecIdentitySearchRef idSearchReference = NULL;
    SecKeychainItemRef itemRef = NULL;
    SecIdentityRef idRef = NULL;
    SecKeychainAttributeList attrList;
    CK_RV rv = CKR_OK;
    int count = 0;
    
    
    if(ulCount > 0 && pTemplate == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    
    
    findObjectsFinal(hSession);
    
    if(mutex.use) {
        mutex.LockMutex(session->myMutex);
    }
    
    /* Find all objects first */
    status = SecIdentitySearchCreate(keychainSlots[session->slot], 0, &idSearchReference);
    if(status != 0) {
        //TODO more specific errors
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        return CKR_GENERAL_ERROR;
    }
    status = SecIdentitySearchCopyNext(idSearchReference, &idRef);
    while(status == 0) {
        
        object = makeObjectFromIdRef(idRef, CKO_CERTIFICATE);
        if(object != NULL && !isCertDuplicated(session, object)) {
            count++;
            addObject(session,object);
            /*
             object = makeObjectFromIdRef(idRef, CKO_PUBLIC_KEY);
             if(object != NULL) {
             count++;
             addObject(session,object);
             }
             */
            object = makeObjectFromIdRef(idRef, CKO_PRIVATE_KEY);
            if(object != NULL) {
                count++;
                addObject(session,object);
            }
        }
        
        status = SecIdentitySearchCopyNext(idSearchReference, &idRef);
    }
    if(status != errSecItemNotFound) {
        freeAllObjects(session);
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        return CKR_GENERAL_ERROR;
    }
    if(idSearchReference) {
        CFRelease(idSearchReference);
    }
    
    attrList.count = 0;
    attrList.attr = NULL;
    
    status = SecKeychainSearchCreateFromAttributes(keychainSlots[session->slot], kSecCertificateItemClass, &attrList, &kcSearchReference);
    if(status != 0) {
        //TODO more specific errors
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        return CKR_GENERAL_ERROR;
    }
    status = SecKeychainSearchCopyNext(kcSearchReference, &itemRef);
    while(status == 0) {
        object = makeObjectFromCertificateRef((SecCertificateRef) itemRef, CKO_CERTIFICATE);
        if(object != NULL && !isCertDuplicated(session, object)) {
            count++;
            addObject(session,object);
            /*
             object = makeObjectFromCertificateRef((SecCertificateRef) itemRef, CKO_PUBLIC_KEY);
             if(object != NULL) {
             count++;
             addObject(session, object);
             }
             */
        }    
        status = SecKeychainSearchCopyNext(kcSearchReference, &itemRef);
    }
    if(status != errSecItemNotFound) {
        freeAllObjects(session);
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        return CKR_GENERAL_ERROR;
    }
    if(kcSearchReference) {
        CFRelease(kcSearchReference);
    }
    
    
    /* Filter out based on tempalte */
    if(ulCount == 0) {
        objectEntry *cur = session->objectList;
        
        debug(DEBUG_VERBOSE,"Requested all objects\n");
        while(cur != NULL) {
            addObjectToSearchResults(session,cur);
			cur = cur->nextObject;
        }
        session->cursor = session->searchList;
        
        if(mutex.use) {
            mutex.UnlockMutex(session->myMutex);
        }
        return CKR_OK;
    }         
    
    
    debug(DEBUG_VERBOSE,"Request template has %u elements\n",ulCount);
    for(i = 0; i < ulCount; i++) {
        if(pTemplate[i].type == CKA_CLASS) {
            CK_ULONG class;
            memcpy(&class, pTemplate[i].pValue, pTemplate[i].ulValueLen);
            
            debug(DEBUG_VERBOSE,"Requested CKA_CLASS = ");
            switch(class) {
                case CKO_CERTIFICATE:
                    rv = findObjectsInitCertificate(session, pTemplate, ulCount );
                    if(mutex.use) {
                        mutex.UnlockMutex(session->myMutex);
                    }
                    return rv;
                    break;
                    
                case CKO_PUBLIC_KEY:
                    rv = findObjectsInitPublicKey(session, pTemplate, ulCount);
                    if(mutex.use) {
                        mutex.UnlockMutex(session->myMutex);
                    }
                    return rv;
                    break;
                    
                case CKO_PRIVATE_KEY:
                    rv = findObjectsInitPrivateKey(session, pTemplate, ulCount);
                    if(mutex.use) {
                        mutex.UnlockMutex(session->myMutex);
                    }
                    return rv;
                    break;   
                    
				case CKO_DATA:
                case CKO_SECRET_KEY:
                case CKO_HW_FEATURE:
                case CKO_DOMAIN_PARAMETERS:
                case CKO_MECHANISM:
                case CKO_OTP_KEY:
                case CKO_NSS_BUILTIN_ROOT_LIST:
                case CKO_NSS_CRL:
                case CKO_NETSCAPE_TRUST:
                    debug(DEBUG_INFO,"unsupported object of type 0x%X (%s)\n", class, getCKOName(class));
                    break;
                default:
                    debug(DEBUG_INFO,"unknown object of type 0x%X (%s)\n", class, getCKOName(class));
                    if(mutex.use) {
                        mutex.UnlockMutex(session->myMutex);
                    }
                    return CKR_ATTRIBUTE_TYPE_INVALID;
            }
        } else {
            debug(DEBUG_INFO,"Requested attribute: 0x%X (%s)\n", pTemplate[i].type, getCKAName(pTemplate[i].type));
            
        }
    }
    
    
    if(mutex.use) {
        mutex.UnlockMutex(session->myMutex);
    }
    return CKR_OK;
    
}

CK_RV
findObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) 
{    
    sessionEntry *session;
    CK_ULONG i = 0;
    
    if(phObject == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if ( ulMaxObjectCount < 0 ) {
        return CKR_ARGUMENTS_BAD;
    }
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(mutex.use) {
        mutex.LockMutex(session->myMutex);
    }
    
    while(session->cursor != NULL) {
        phObject[i++] = session->cursor->object->id;
        session->cursor = session->cursor->next;
        if(i >= ulMaxObjectCount) {
            break;
        }
    }
    *pulObjectCount = i;
    
    if(mutex.use) {
        mutex.UnlockMutex(session->myMutex);
    }
    return CKR_OK;
    
}

CK_RV
findObjectsFinal(CK_SESSION_HANDLE hSession)
{
    sessionEntry *session;
    objectEntry *cur;
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    freeObjectSearchList(session);
    
    debug(DEBUG_VERBOSE,"Valid object ids: ");
    cur = session->objectList;
    while(cur != NULL) {
        debug(DEBUG_VERBOSE,"%u ",cur->id);
        cur = cur->nextObject;
    }
    debug(DEBUG_VERBOSE,"\n");
    
    return CKR_OK;
}

CK_RV
encryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    sessionEntry *session = NULL;
    objectEntry *object = NULL;
    OSStatus status = 0;
    CK_RV returnVal = CKR_OK;
    const CSSM_KEY *cssmKey = NULL;
    CSSM_ALGORITHMS algorithmID = CSSM_ALGID_NONE;
    CSSM_PADDING paddingID = CSSM_PADDING_NONE;
    CSSM_ACCESS_CREDENTIALS creds;
    CSSM_CSP_HANDLE cspHandle;
    SecKeyRef pubKeyRef = NULL;
    CSSM_CONTEXT_ATTRIBUTE newAttr;
	
    session = findSessionEntry(hSession);
    if(session == NULL)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    object = getObject(session, hKey);
    if(object == NULL)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    algorithmID = pMechanismToCSSM_ALGID(pMechanism);
    if(algorithmID == CKR_MECHANISM_PARAM_INVALID || algorithmID == CKR_MECHANISM_INVALID) {
        returnVal = algorithmID;
        goto cleanup;
    }
    switch(algorithmID) {
        case CSSM_ALGID_RSA:
        case CSSM_ALGID_MD2WithRSA:
        case CSSM_ALGID_MD5WithRSA:
        case CSSM_ALGID_SHA1WithRSA:
            paddingID = CSSM_PADDING_PKCS1;
        default:
            paddingID = CSSM_PADDING_NONE;
    }
    
    status = getPublicKeyRefForObject(object, &pubKeyRef);
    if (status != 0)
    {
        debug(DEBUG_WARNING,"Error in getPublicKeyRefForObject\n");
        returnVal = CKR_OBJECT_HANDLE_INVALID;
        goto cleanup;
    }
    assert(pubKeyRef);
    status = SecKeyGetCSPHandle(pubKeyRef, &cspHandle);
    if (status != 0)
    {
        debug(DEBUG_WARNING,"Error in SecKeyGetCSPHandle\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    status = SecKeyGetCSSMKey(pubKeyRef, &cssmKey);
    if (status != 0)
    {
        debug(DEBUG_WARNING,"Error getting CSSMKey\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    memset(&creds, 0, sizeof(CSSM_ACCESS_CREDENTIALS));
    CSSM_DeleteContext(session->encryptContext);
    session->encryptContext = 0;
    status = CSSM_CSP_CreateAsymmetricContext(cspHandle, algorithmID, &creds, cssmKey, paddingID, &(session->encryptContext));
    if(status != 0)
    {
        cssmPerror("CreateAsymmetricContext", status);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    newAttr.AttributeType = CSSM_ATTRIBUTE_PUBLIC_KEY;
    newAttr.AttributeLength = sizeof(CSSM_KEY);
    newAttr.Attribute.Data = (CSSM_DATA_PTR)cssmKey;
    status = CSSM_UpdateContextAttributes(session->encryptContext, 1, &newAttr);
    if(status != 0)
    {
        cssmPerror("UpdateContextAttributes", status);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
	
cleanup:
    return returnVal;
}

CK_RV
c_encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    sessionEntry *session = NULL;
    CSSM_DATA plainText, cipherText, extra;
    UInt32 bytesEncrypted = 0;
    CSSM_RETURN status = 0;
    CK_RV ret = CKR_OK;
	
    session = findSessionEntry(hSession);
    if(session == NULL)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(session->encryptContext == 0) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    plainText.Data = pData;
    plainText.Length = ulDataLen;
	
    if(pEncryptedData == NULL)
    {
        // cipherText will be created by CSSM_EncryptData, we are responsible for freeing it when done
        cipherText.Data = NULL;
        cipherText.Length = 0;
    }
    else
    {
        cipherText.Data = pEncryptedData;
        cipherText.Length = *(pulEncryptedDataLen);
    }
    status = CSSM_EncryptData(session->encryptContext, &plainText, 1, &cipherText, 1, &bytesEncrypted, &extra);
    if(status != 0)
    {
        if (status == CSSMERR_CSP_OUTPUT_LENGTH_ERROR)
        {
            /* dont delete the context yet */
            if(pEncryptedData == NULL && cipherText.Data != NULL)
            {
                free(cipherText.Data);
            }
            return CKR_BUFFER_TOO_SMALL;
        }
        else if (status == CSSMERR_CSP_INVALID_DATA)
        {
            ret = CKR_DATA_INVALID;
            goto cleanup;
        }
        else
        {
            cssmPerror("EncryptData",status);
            ret = CKR_GENERAL_ERROR;
            goto cleanup;
        }
    }
    *pulEncryptedDataLen = bytesEncrypted;
	
cleanup:
    if(pEncryptedData == NULL)
    {
        free(cipherText.Data);
    }
    CSSM_DeleteContext(session->encryptContext);
    session->encryptContext = 0;
	
    return ret;
}

CK_RV
decryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    sessionEntry *session = NULL;
    objectEntry *object = NULL;
    OSStatus status = 0;
    CSSM_RETURN ret = 0;
    CK_RV returnVal = CKR_OK;
    const CSSM_KEY *cssmKey = NULL;
    CSSM_ALGORITHMS algorithmID = CSSM_ALGID_NONE;
    CSSM_PADDING paddingID = CSSM_PADDING_NONE;
    
    CSSM_CSP_HANDLE cspHandle;
    const CSSM_ACCESS_CREDENTIALS *cssmCreds = NULL;
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    object = getObject(session, hKey);
    if(object == NULL) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    if(session->decryptContext != 0) {
        CSSM_DeleteContext(session->decryptContext);
        session->decryptContext = 0;
    }
    
    if(!session->loggedIn) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    
    algorithmID = pMechanismToCSSM_ALGID(pMechanism);
    if(algorithmID == CKR_MECHANISM_PARAM_INVALID || algorithmID == CKR_MECHANISM_INVALID) {
        returnVal = algorithmID;
        goto cleanup;
    }
    switch(algorithmID) {
        case CSSM_ALGID_RSA:
        case CSSM_ALGID_MD2WithRSA:
        case CSSM_ALGID_MD5WithRSA:
        case CSSM_ALGID_SHA1WithRSA:
            paddingID = CSSM_PADDING_PKCS1;
        default:
            paddingID = CSSM_PADDING_NONE;
    }
    
    status = SecKeychainGetCSPHandle(keychainSlots[session->slot], &cspHandle);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error in SecKeychainGetCSPHandle\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    status = SecKeyGetCredentials(object->storage.privateKey.keyRef, CSSM_ACL_AUTHORIZATION_DECRYPT, kSecCredentialTypeNoUI, &cssmCreds);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error in SecKeyGetCredentials\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    status = SecKeyGetCSSMKey(object->storage.privateKey.keyRef, &cssmKey);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error getting CSSMKey\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    ret = CSSM_CSP_CreateAsymmetricContext(cspHandle, algorithmID, cssmCreds, cssmKey, paddingID, &(session->decryptContext));
    if(ret != 0) {
        cssmPerror("CreateAsymmetricContext", status);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
cleanup:
    
    return returnVal;
}

CK_RV
decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDecryptedData, CK_ULONG_PTR pulDecryptedDataLen) 
{
    sessionEntry *session = NULL;
    CSSM_DATA input, output, extra;    
    UInt32 bytesDecrypted = 0;
    CSSM_RETURN status = 0;
    CK_RV ret = CKR_OK;
    
    
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(!session->loggedIn) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    
    if(session->decryptContext == 0) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    input.Data = pData;
    input.Length = ulDataLen;
    
    if(pDecryptedData == NULL) {
        /* output will be created by CSSM_DecryptData, we are 
         * responsible for free'ing it when done
         */
        output.Data = NULL;
        output.Length = 0;
    } else {
        output.Data = pDecryptedData;
        output.Length = *(pulDecryptedDataLen);
    }
    
    status = CSSM_DecryptData(session->decryptContext, &input, 1, &output, 1, &bytesDecrypted, &extra);
    if(status != 0) {
        if (status == CSSMERR_CSP_OUTPUT_LENGTH_ERROR) {
            /* dont delete the context yet */
            if(pDecryptedData == NULL && output.Data != NULL) {
                free(output.Data);
            }
            return CKR_BUFFER_TOO_SMALL; 
        } else if (status == CSSMERR_CSP_INVALID_DATA) {
            ret = CKR_DATA_INVALID;
            goto cleanup;
        } else {
            cssmPerror("DecryptData",status);
            ret = CKR_GENERAL_ERROR;
            goto cleanup;
        }
        
    }
    
    
    *pulDecryptedDataLen = bytesDecrypted;
    
cleanup:
    if(pDecryptedData == NULL) {
        free(output.Data);
    }
    CSSM_DeleteContext(session->decryptContext);
    session->decryptContext = 0;
    
    return ret;
}

CK_RV
signInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    sessionEntry *session = NULL;
    objectEntry *object = NULL;
    OSStatus status = 0;
    CSSM_RETURN ret = CSSM_OK;
    CK_RV returnVal = CKR_OK;
    CSSM_CSP_HANDLE cspHandle = 0;
    const CSSM_ACCESS_CREDENTIALS *cssmCreds = NULL;
    const CSSM_KEY *cssmKey = NULL;
    CSSM_ALGORITHMS algorithmID = CSSM_ALGID_NONE;
    CSSM_VERSION cmVersion;
    CSSM_GUID cmGUID;
    CSSM_PVC_MODE cmPvcPolicy;
    SecKeychainRef keychainRef;
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    object = getObject(session, hKey);
    if(object == NULL) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    CSSM_DeleteContext(session->signContext);
    session->signContext = 0;
    
    if(!session->loggedIn) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    
    if (object->class != CKO_PRIVATE_KEY) {
        debug(DEBUG_INFO,"Object specified is not a private key\n");
        returnVal = CKR_KEY_HANDLE_INVALID;
        goto cleanup;
    }
    
    if(pMechanism == NULL) {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    
    algorithmID = pMechanismToCSSM_ALGID(pMechanism);
    if(algorithmID == CKR_MECHANISM_PARAM_INVALID || algorithmID == CKR_MECHANISM_INVALID) {
        return algorithmID;
    }
    session->signAlgorithm = CKR_MECHANISM_INVALID;
    
    cmPvcPolicy = CSSM_PVC_NONE;
    cmVersion.Major = 2;
    cmVersion.Minor = 0;    
    
    ret = CSSM_Init(&cmVersion, CSSM_PRIVILEGE_SCOPE_PROCESS, &cmGUID, CSSM_KEY_HIERARCHY_NONE, &cmPvcPolicy, (const void *)NULL);
    if (ret != 0) {
        cssmPerror("CSSM_Init", ret);
        return CKR_GENERAL_ERROR;
    }
    
    status = SecKeyGetCSSMKey(object->storage.privateKey.keyRef, &cssmKey);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error getting CSSMKey (status = %d)\n", status);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    status = SecKeychainItemCopyKeychain((SecKeychainItemRef)object->storage.privateKey.keyRef, &keychainRef);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error in SecKeychainItemCopyKeychain\n");
        goto cleanup;
    }
    
    
    status = SecKeychainGetCSPHandle(keychainRef, &cspHandle);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error in SecKeychainGetCSPHandle\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    
    status = SecKeyGetCredentials(object->storage.privateKey.keyRef, CSSM_ACL_AUTHORIZATION_SIGN, kSecCredentialTypeNoUI, &cssmCreds);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error in SecKeyGetCredentials (status = %d)\n", status);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    ret = CSSM_CSP_CreateSignatureContext(cspHandle, algorithmID, cssmCreds, cssmKey, &(session->signContext));
    if (ret != 0) {
        cssmPerror("CSSM_CreateSignatureContext", ret);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
cleanup:
    
    return returnVal;
}

CK_RV
sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) 
{
    sessionEntry *session = NULL;
    CSSM_DATA input, output;    
    CSSM_RETURN status = 0;
    CK_RV ret = CKR_OK;
    
    
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(!session->loggedIn) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    
    if(session->signContext == 0) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    input.Data = pData;
    input.Length = ulDataLen;
    
    output.Data = pSignature;
    output.Length = *(pulSignatureLen);
    
    
    status = CSSM_SignData(session->signContext, &input, 1, CSSM_ALGID_NONE, &output);
    if(status != 0) {
        /* dont delete the context yet */
        cssmPerror("SignData",status);
        if(status == CSSMERR_CSP_OPERATION_AUTH_DENIED) {
			ret = CKR_FUNCTION_REJECTED;
        } else if(status == CSSMERR_CSP_OUTPUT_LENGTH_ERROR) {
            ret = CKR_BUFFER_TOO_SMALL;
        } else {
            ret = CKR_GENERAL_ERROR;
        }
        return ret;
    } else {
		*pulSignatureLen = output.Length;
    }
    
    CSSM_DeleteContext(session->signContext);
    session->signContext = 0;
    
    
    return ret;
}

CK_RV
signUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	sessionEntry *session = NULL;
    CSSM_DATA input;    
    CSSM_RETURN status = 0;
    CK_RV ret = CKR_OK;
    
    
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(!session->loggedIn) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    
    if(session->signContext == 0) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    
    input.Data = pPart;
    input.Length = ulPartLen;
    
    
    status = CSSM_SignDataUpdate(session->signContext, &input, 1);
    if(status != 0) {
        cssmPerror("SignDataUpdate",status);
        ret = CKR_GENERAL_ERROR;
    }
    
    
    return ret;
}

CK_RV
signFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	sessionEntry *session = NULL;
    CSSM_DATA output;    
    CSSM_RETURN status = 0;
    CK_RV ret = CKR_OK;
    
    
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if(!session->loggedIn) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    
    if(session->signContext == 0) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
	
	output.Data = pSignature;
    output.Length = 0;    
    
    status = CSSM_SignDataFinal(session->signContext, &output);
    if(status != 0) {
		if(status == CSSMERR_CSP_OPERATION_AUTH_DENIED) {
			ret = CKR_FUNCTION_REJECTED;
		} else {
			ret = CKR_GENERAL_ERROR;
		}
    }
	
	*pulSignatureLen = output.Length;
    
    
    return ret;
}

CK_RV
verifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    sessionEntry *session = NULL;
    objectEntry *object = NULL;
    OSStatus status = 0;
    CSSM_RETURN ret = CSSM_OK;
    CK_RV returnVal = CKR_OK;
    CSSM_CSP_HANDLE cspHandle = 0;
    const CSSM_KEY *cssmKey = NULL;
    CSSM_ALGORITHMS algorithmID = CSSM_ALGID_NONE;
    SecKeyRef pubKeyRef = NULL;
	
    session = findSessionEntry(hSession);
    if(session == NULL)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    object = getObject(session, hKey);
    if(object == NULL)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    algorithmID = pMechanismToCSSM_ALGID(pMechanism);
    if(algorithmID == CKR_MECHANISM_PARAM_INVALID || algorithmID == CKR_MECHANISM_INVALID) {
        returnVal = algorithmID;
        goto cleanup;
    }
    
    status = getPublicKeyRefForObject(object, &pubKeyRef);
    if (status != 0)
    {
        debug(DEBUG_WARNING,"Error in getPublicKeyRefForObject\n");
        returnVal = CKR_OBJECT_HANDLE_INVALID;
        goto cleanup;
    }
    assert(pubKeyRef);
    status = SecKeyGetCSPHandle(pubKeyRef, &cspHandle);
    if (status != 0)
    {
        debug(DEBUG_WARNING,"Error in SecKeyGetCSPHandle\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    status = SecKeyGetCSSMKey(pubKeyRef, &cssmKey);
    if (status != 0)
    {
        debug(DEBUG_WARNING,"Error getting CSSMKey\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    CSSM_DeleteContext(session->verifyContext);
    session->verifyContext = 0;
    ret = CSSM_CSP_CreateSignatureContext(cspHandle, algorithmID, NULL, cssmKey, &(session->verifyContext));
    if (ret != 0)
    {
        cssmPerror("CSSM_CreateSignatureContext", ret);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
cleanup:
	
    return returnVal;
}

CK_RV
c_verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    sessionEntry *session = NULL;
    CSSM_DATA inData, signature;
    CSSM_RETURN status = 0;
    CK_RV ret = CKR_OK;
	
    session = findSessionEntry(hSession);
    if(session == NULL)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    inData.Data = pData;
    inData.Length = ulDataLen;
    signature.Data = pSignature;
    signature.Length = ulSignatureLen;
    if(session->verifyContext == 0) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    status = CSSM_VerifyData(session->verifyContext, &inData, 1, CSSM_ALGID_NONE, &signature);
    if(status != 0)
    {
        if(status == CSSMERR_CSP_OUTPUT_LENGTH_ERROR)
        {
            /* dont delete the context yet */
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            cssmPerror("VerifyData",status);
            ret = CKR_GENERAL_ERROR;
        }
    }
    CSSM_DeleteContext(session->verifyContext);
    session->verifyContext;
	
	return ret;
}

CK_RV
seedRandom(CK_SESSION_HANDLE hSession ,CK_BYTE_PTR data,CK_ULONG dataLen)
{
    return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_RV
generateRandom(CK_SESSION_HANDLE hSession ,CK_BYTE_PTR data,CK_ULONG dataLen) 
{
    sessionEntry *session = NULL;
    CSSM_CC_HANDLE randomHandle;
    CSSM_DATA randomData;
    OSStatus status = 0;
    
    CSSM_RETURN ret = CSSM_OK;
    CK_RV returnVal = CKR_OK;
    CSSM_CSP_HANDLE cspHandle = 0;
    CSSM_VERSION cmVersion;
    CSSM_GUID cmGUID;
    CSSM_PVC_MODE cmPvcPolicy;
    
    
    session = findSessionEntry(hSession);
    if(session == NULL) {
        returnVal = CKR_SESSION_HANDLE_INVALID;
        goto cleanup;
    }
    
    cmPvcPolicy = CSSM_PVC_NONE;
    cmVersion.Major = 2;
    cmVersion.Minor = 0;    
    
    ret = CSSM_Init(&cmVersion, CSSM_PRIVILEGE_SCOPE_PROCESS, &cmGUID, CSSM_KEY_HIERARCHY_NONE, &cmPvcPolicy, (const void *)NULL);
    if (ret != 0) {
        cssmPerror("CSSM_Init", ret);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    
    status = SecKeychainGetCSPHandle(keychainSlots[session->slot], &cspHandle);
    if (status != 0) {
        debug(DEBUG_WARNING,"Error in SecKeychainGetCSPHandle\n");
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    
    ret = CSSM_CSP_CreateRandomGenContext(cspHandle, CKM_RSA_PKCS, NULL, dataLen, &randomHandle);
    if (ret != 0) {
        cssmPerror("CSSM_CSP_CreateRandomGenContext", ret);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
    randomData.Data = data;
    randomData.Length = dataLen;
    
    ret = CSSM_GenerateRandom(randomHandle, &randomData);
    if (ret != 0) {
        cssmPerror("CSSM_GenerateRandom", ret);
        returnVal = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    
cleanup:
    
    return returnVal;
}