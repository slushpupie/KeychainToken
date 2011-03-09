/*
 *  keychain_pkcs11.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/22/09.
 *  Copyright 2009 All rights reserved.
 *
 */

#ifndef _KEYCHAIN_PKCS11_H_
#define _KEYCHAIN_PKCS11_H_


#include <Carbon/Carbon.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFPreferences.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>
#include <Security/cssm.h>
#include <openssl/x509.h>
#include <time.h>

#include "mypkcs11.h"
#include "types.h"
#include "constants.h"

#include "support_funcs.h"
#include "debug.h"
#include "preferences.h"










static CK_INFO ckInfo = {
{2, 11},
"KeychainToken",
0,
"Apple Keychain PKCS#11         ",
{0, 1}
};

CK_BBOOL initialized = CK_FALSE;
SecKeychainRef keychainSlots[MAX_SLOTS];
sessionEntry *firstSession;
CK_SESSION_HANDLE sessionCounter = 0;
static mechInfo mechanismList[] = { {CKM_RSA_PKCS, { 1024, 4096, CKF_HW | CKF_SIGN | CKF_DECRYPT } } };
static unsigned long numMechanisms = sizeof(mechanismList)/sizeof(mechInfo);
mutexFunctions mutex;

UInt8 unique = 0;

/* macro for unimplemented functions */
#define NOTSUPPORTED(name, args) \
CK_RV name args \
{ \
    debug(DEBUG_CRITICAL, #name " called (NOTSUPPORTED)\n"); \
    return CKR_FUNCTION_NOT_SUPPORTED; \
}

/* macro for implemented functions that do not require initialization first */
#define REQUIRED(name, name2, dec_args, use_args) \
CK_RV name2 dec_args ; \
CK_RV name dec_args \
{ \
    CK_RV rv = CKR_OK; \
    debug(DEBUG_CRITICAL, #name " called\n"); \
    rv = name2 use_args ; \
    debug(DEBUG_CRITICAL, #name " returned %s (0x%X)\n", getCKRName(rv), rv); \
    return rv; \
}

/* macro for implemented functions that require initialization first */
#define SUPPORTED(name, name2, dec_args, use_args) \
CK_RV name2 dec_args ; \
CK_RV name dec_args \
{ \
    CK_RV rv = CKR_OK; \
    debug(DEBUG_CRITICAL, #name " called\n"); \
    if( ! initialized ) { \
        return CKR_CRYPTOKI_NOT_INITIALIZED; \
    } \
    rv = name2 use_args; \
    debug(DEBUG_CRITICAL, #name " returned %s (0x%X)\n", getCKRName(rv), rv); \
    return rv; \
}


/*
 * PKCS#11 Function Map:  Map our functions to the correct symbol names. In the
 * order of the PKCS#11 interface standard document for easy searching.
 */

REQUIRED(C_Initialize, initialize,
         (CK_VOID_PTR pInitArgs),
         (pInitArgs))
REQUIRED(C_Finalize, finalize,
         (CK_VOID_PTR pReserved),
         (pReserved))
SUPPORTED(C_GetInfo, getInfo,
          (CK_INFO_PTR pInfo),
          (pInfo))
/* C_GetFunctionList defined below */
SUPPORTED(C_GetSlotList, getSlotList,
          (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount),
          (tokenPresent, pSlotList, pulCount))
SUPPORTED(C_GetSlotInfo, getSlotInfo,
          (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo),
          (slotID, pInfo))
SUPPORTED(C_GetTokenInfo, getTokenInfo,
          (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo),
          (slotID, pInfo))
SUPPORTED(C_WaitForSlotEvent, waitForSlotEvent,
          (CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved),
          (flags, pSlot, pReserved))
SUPPORTED(C_GetMechanismList, getMechanismList,
          (CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount),
          (slotID, pMechanismList, pulCount))
SUPPORTED(C_GetMechanismInfo, getMechanismInfo,
          (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo),
          (slotID, type, pInfo))
NOTSUPPORTED(C_InitToken, (CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel))
NOTSUPPORTED(C_InitPIN, (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen))
NOTSUPPORTED(C_SetPIN, (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen))
SUPPORTED(C_OpenSession, openSession,
          (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession),
          (slotID, flags, pApplication, Notify, phSession))
SUPPORTED(C_CloseSession, closeSession,
          (CK_SESSION_HANDLE hSession),
          (hSession))
SUPPORTED(C_CloseAllSessions, closeAllSessions,
          (CK_SLOT_ID slotID),
          (slotID))
SUPPORTED(C_GetSessionInfo, getSessionInfo,
          (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo),
          (hSession, pInfo) )
NOTSUPPORTED(C_GetOperationState, (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen))
NOTSUPPORTED(C_SetOperationState, (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationkey))
SUPPORTED(C_Login, login,
          (CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen),
          (hSession, userType, pPin, ulPinLen))
SUPPORTED(C_Logout, logout,
          (CK_SESSION_HANDLE hSession),
          (hSession))
NOTSUPPORTED(C_CreateObject, (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject))
NOTSUPPORTED(C_CopyObject, (CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_OBJECT_HANDLE_PTR phNewObject))
NOTSUPPORTED(C_DestroyObject, (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject))
NOTSUPPORTED(C_GetObjectSize, (CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ULONG_PTR pulSize))
SUPPORTED(C_GetAttributeValue, getAttributeValue,
          (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount),
          (hSession, hObject, pTemplate, ulCount))
NOTSUPPORTED(C_SetAttributeValue, (CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTempalte,CK_ULONG ulCount))
SUPPORTED(C_FindObjectsInit, findObjectsInit,
          (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount),
          (hSession, pTemplate, ulCount))
SUPPORTED(C_FindObjects, findObjects,
          (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount),
          (hSession, phObject, ulMaxObjectCount, pulObjectCount))
SUPPORTED(C_FindObjectsFinal, findObjectsFinal,
          (CK_SESSION_HANDLE hSession),
          (hSession))
SUPPORTED(C_EncryptInit, encryptInit,
		  (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey),
		  (hSession, pMechanism, hKey))
SUPPORTED(C_Encrypt, c_encrypt,
		  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen),
		  (hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen))
NOTSUPPORTED(C_EncryptUpdate, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen,CK_BYTE_PTR pEncryptedPart,CK_ULONG_PTR pulEncryptedPartLen))
NOTSUPPORTED(C_EncryptFinal, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pLastEncryptedPart,CK_ULONG_PTR pulLastEncryptedPartLen))
SUPPORTED(C_DecryptInit, decryptInit,
          (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey),
          (hSession, pMechanism, hKey))
SUPPORTED(C_Decrypt, decrypt,
          (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDecryptedData, CK_ULONG_PTR pulDecryptedDataLen),
          (hSession, pData, ulDataLen, pDecryptedData, pulDecryptedDataLen))
NOTSUPPORTED(C_DecryptUpdate,(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedPart,CK_ULONG ulEncryptedPartLen,CK_BYTE_PTR pPart,CK_ULONG_PTR pulPartLen))
NOTSUPPORTED(C_DecryptFinal, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR plastPart,CK_ULONG_PTR pulLastPartLen))
NOTSUPPORTED(C_DigestInit, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism))
NOTSUPPORTED(C_Digest, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen))
NOTSUPPORTED(C_DigestUpdate, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG pPartLen))
NOTSUPPORTED(C_DigestKey, (CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hKey))
NOTSUPPORTED(C_DigestFinal, (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen))
SUPPORTED(C_SignInit, signInit,
          (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey),
          (hSession, pMechanism, hKey))
SUPPORTED(C_Sign, sign,
          (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen),
          (hSession, pData, ulDataLen, pSignature, pulSignatureLen))
SUPPORTED(C_SignUpdate, signUpdate,
          (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen),
          (hSession, pPart, ulPartLen))
SUPPORTED(C_SignFinal, signFinal,
          (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen),
          (hSession, pSignature, pulSignatureLen))
NOTSUPPORTED(C_SignRecoverInit, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey))
NOTSUPPORTED(C_SignRecover, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen))
SUPPORTED(C_VerifyInit, verifyInit,
		  (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey),
		  (hSession, pMechanism, hKey))
SUPPORTED(C_Verify, c_verify,
		  (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen),
		  (hSession, pData, ulDataLen, pSignature, ulSignatureLen))
NOTSUPPORTED(C_VerifyUpdate, (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen))
NOTSUPPORTED(C_VerifyFinal, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen))
NOTSUPPORTED(C_VerifyRecoverInit, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey))
NOTSUPPORTED(C_VerifyRecover, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen,CK_BYTE_PTR pData,CK_ULONG_PTR pulDataLen))
NOTSUPPORTED(C_DigestEncryptUpdate, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen,CK_BYTE_PTR pEncryptedPart,CK_ULONG_PTR pulEncryptedPartLen))
NOTSUPPORTED(C_DecryptDigestUpdate, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedPart,CK_ULONG ulEncryptedPartLen,CK_BYTE_PTR pPart,CK_ULONG_PTR pulPartLen))
NOTSUPPORTED(C_SignEncryptUpdate, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen,CK_BYTE_PTR pEncryptedPart,CK_ULONG_PTR pulEncryptedPartLen))
NOTSUPPORTED(C_DecryptVerifyUpdate, (CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedPart,CK_ULONG ulEncryptedPartLen,CK_BYTE_PTR pPart,CK_ULONG_PTR pulPartLen))
NOTSUPPORTED(C_GenerateKey, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_OBJECT_HANDLE_PTR phKey))
NOTSUPPORTED(C_GenerateKeyPair, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_ATTRIBUTE_PTR pPublicKeyTempate,CK_ULONG ulPublicKeyAttributeCount,CK_ATTRIBUTE_PTR pPrivateKeyTemplate,CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey,CK_OBJECT_HANDLE_PTR phPrivateKey))
NOTSUPPORTED(C_WrapKey, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hWrappingKey,CK_OBJECT_HANDLE hKey,CK_BYTE_PTR pWrappedKey,CK_ULONG_PTR pulWrappedKeyLen))
NOTSUPPORTED(C_UnwrapKey, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hUnwrappingKey,CK_BYTE_PTR pWrappedKey,CK_ULONG ulWrappedKeyLen,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulAttributeCount,CK_OBJECT_HANDLE_PTR phKey))
NOTSUPPORTED(C_DeriveKey, (CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hBaseKey,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulAttributeCount,CK_OBJECT_HANDLE_PTR phKey))
SUPPORTED(C_SeedRandom, seedRandom,
          (CK_SESSION_HANDLE hSession ,CK_BYTE_PTR data,CK_ULONG dataLen),
          (hSession, data, dataLen))
SUPPORTED(C_GenerateRandom, generateRandom,
          (CK_SESSION_HANDLE hSession ,CK_BYTE_PTR data,CK_ULONG dataLen),
          (hSession, data, dataLen))
NOTSUPPORTED(C_GetFunctionStatus, (CK_SESSION_HANDLE hSession))
NOTSUPPORTED(C_CancelFunction, (CK_SESSION_HANDLE hSession))


CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr);

#undef  CK_NEED_ARG_LIST
#undef  CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO( func ) ( CK_ ## func ) func ,

static CK_FUNCTION_LIST
functionList =  {
    {2, 20}, // PKCS #11 spec version we support
#include "pkcs11f.h"
};

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr)
{
    if( pPtr == NULL ) {
        return CKR_ARGUMENTS_BAD;
    }
    *pPtr = &functionList;
    return CKR_OK;
}


#endif
