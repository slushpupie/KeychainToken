/*
 *  keychain_pkcs11.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/22/09.
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

#include "pkcs11.h"
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

static CK_FUNCTION_LIST
functionList =  {
    {2, 20}, // PKCS #11 spec version we support
    (CK_C_Initialize) C_Initialize,
    (CK_C_Finalize) C_Finalize,
    (CK_C_GetInfo) C_GetInfo,
    (CK_C_GetFunctionList) C_GetFunctionList,
    (CK_C_GetSlotList) C_GetSlotList,
    (CK_C_GetSlotInfo) C_GetSlotInfo,
    (CK_C_GetTokenInfo) C_GetTokenInfo,
    (CK_C_GetMechanismList) C_GetMechanismList,
    (CK_C_GetMechanismInfo) C_GetMechanismInfo,
    (CK_C_InitToken) C_InitToken,
    (CK_C_InitPIN) C_InitPIN,
    (CK_C_SetPIN) C_SetPIN,
    (CK_C_OpenSession) C_OpenSession,
    (CK_C_CloseSession) C_CloseSession,
    (CK_C_CloseAllSessions) C_CloseAllSessions,
    (CK_C_GetSessionInfo) C_GetSessionInfo,
    (CK_C_GetOperationState) C_GetOperationState,
    (CK_C_SetOperationState) C_SetOperationState,
    (CK_C_Login) C_Login,
    (CK_C_Logout) C_Logout,
    (CK_C_CreateObject) C_CreateObject,
    (CK_C_CopyObject) C_CopyObject,
    (CK_C_DestroyObject) C_DestroyObject,
    (CK_C_GetObjectSize) C_GetObjectSize,
    (CK_C_GetAttributeValue) C_GetAttributeValue,
    (CK_C_SetAttributeValue) C_SetAttributeValue,
    (CK_C_FindObjectsInit) C_FindObjectsInit,
    (CK_C_FindObjects) C_FindObjects,
    (CK_C_FindObjectsFinal) C_FindObjectsFinal,
    (CK_C_EncryptInit) C_EncryptInit,
    (CK_C_Encrypt) C_Encrypt,
    (CK_C_EncryptUpdate) C_EncryptUpdate,
    (CK_C_EncryptFinal) C_EncryptFinal,
    (CK_C_DecryptInit) C_DecryptInit,
    (CK_C_Decrypt) C_Decrypt,
    (CK_C_DecryptUpdate) C_DecryptUpdate,
    (CK_C_DecryptFinal) C_DecryptFinal,
    (CK_C_DigestInit) C_DigestInit,
    (CK_C_Digest) C_Digest,
    (CK_C_DigestUpdate) C_DigestUpdate,
    (CK_C_DigestKey) C_DigestKey,
    (CK_C_DigestFinal) C_DigestFinal,
    (CK_C_SignInit) C_SignInit,
    (CK_C_Sign) C_Sign,
    (CK_C_SignUpdate) C_SignUpdate,
    (CK_C_SignFinal) C_SignFinal,
    (CK_C_SignRecoverInit) C_SignRecoverInit,
    (CK_C_SignRecover) C_SignRecover,
    (CK_C_VerifyInit) C_VerifyInit,
    (CK_C_Verify) C_Verify,
    (CK_C_VerifyUpdate) C_VerifyUpdate,
    (CK_C_VerifyFinal) C_VerifyFinal,
    (CK_C_VerifyRecoverInit) C_VerifyRecoverInit,
    (CK_C_VerifyRecover) C_VerifyRecover,
    (CK_C_DigestEncryptUpdate) C_DigestEncryptUpdate,
    (CK_C_DecryptDigestUpdate) C_DecryptDigestUpdate,
    (CK_C_SignEncryptUpdate) C_SignEncryptUpdate,
    (CK_C_DecryptVerifyUpdate) C_DecryptVerifyUpdate,
    (CK_C_GenerateKey) C_GenerateKey,
    (CK_C_GenerateKeyPair) C_GenerateKeyPair,
    (CK_C_WrapKey) C_WrapKey,
    (CK_C_UnwrapKey) C_UnwrapKey,
    (CK_C_DeriveKey) C_DeriveKey,
    (CK_C_SeedRandom) C_SeedRandom,
    (CK_C_GenerateRandom) C_GenerateRandom,
    (CK_C_GetFunctionStatus) C_GetFunctionStatus,
    (CK_C_CancelFunction) C_CancelFunction,
    (CK_C_WaitForSlotEvent) C_WaitForSlotEvent,
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
