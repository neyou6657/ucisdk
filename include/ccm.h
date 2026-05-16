#ifndef CCM_H
#define CCM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CCM_OK 0
#define CCM_ERR_INVALID_ARGUMENT -1
#define CCM_ERR_UNSUPPORTED_ALGORITHM -2
#define CCM_ERR_BUFFER_TOO_SMALL -3

/*
 * CCM top-level unified crypto service API.
 *
 * Public interface categories:
 * 1. Environment
 * 2. Crypto operations: hash, MAC, symmetric encryption, asymmetric encryption
 * 3. Key management: generation, import/export, KEM, agreement, hybrid agreement
 * 4. Digital signature: sign, verify, digest sign/verify, hybrid sign/verify
 *
 * The top layer normalizes all calls into the existing domain + action + algorithm
 * request model. Device-specific classes, certificate operations, and message
 * wrappers are intentionally not part of this public interface.
 */

typedef enum {
    CCM_ALG_AUTO = 0,
    CCM_ALG_SM2,
    CCM_ALG_SM2_SIGN,
    CCM_ALG_SM2_ENC,
    CCM_ALG_RSA,
    CCM_ALG_RSA_SIGN,
    CCM_ALG_RSA_ENC,
    CCM_ALG_SM3,
    CCM_ALG_SHA256,
    CCM_ALG_SM4_CBC,
    CCM_ALG_SM4_ECB,
    CCM_ALG_SM4_MAC,
    CCM_ALG_AES_CBC,
    CCM_ALG_AES_ECB,
    CCM_ALG_KYBER512,
    CCM_ALG_KYBER768,
    CCM_ALG_KYBER1024,
    CCM_ALG_MLKEM768,
    CCM_ALG_DILITHIUM2,
    CCM_ALG_DILITHIUM3,
    CCM_ALG_DILITHIUM5,
    CCM_ALG_SM9
} ccm_algorithm_id_t;

typedef enum {
    CCM_KEY_USAGE_NONE = 0,
    CCM_KEY_USAGE_SIGN,
    CCM_KEY_USAGE_VERIFY,
    CCM_KEY_USAGE_ENCRYPT,
    CCM_KEY_USAGE_DECRYPT,
    CCM_KEY_USAGE_WRAP,
    CCM_KEY_USAGE_DERIVE,
    CCM_KEY_USAGE_KEM,
    CCM_KEY_USAGE_AGREEMENT
} ccm_key_usage_t;

typedef enum {
    CCM_KEY_SOURCE_NONE = 0,
    CCM_KEY_SOURCE_INTERNAL_INDEX,
    CCM_KEY_SOURCE_SESSION_HANDLE,
    CCM_KEY_SOURCE_EXTERNAL_KEY
} ccm_key_source_t;

typedef enum {
    CCM_MODE_NONE = 0,
    CCM_MODE_ECB,
    CCM_MODE_CBC,
    CCM_MODE_CTR,
    CCM_MODE_GCM,
    CCM_MODE_CCM,
    CCM_MODE_OFB,
    CCM_MODE_CFB
} ccm_cipher_mode_t;

typedef enum {
    CCM_PADDING_NONE = 0,
    CCM_PADDING_PKCS7,
    CCM_PADDING_PSS,
    CCM_PADDING_OAEP
} ccm_padding_t;

typedef struct {
    unsigned int uiAlgID;
    unsigned int uiUsage;
    unsigned int uiSource;
    unsigned int uiKeyIndex;
    void *hKeyHandle;
    void *pExternalKey;
} Unif_KeyRef;

typedef struct {
    unsigned char *pucData;
    unsigned int uiDataLen;
} Unif_Buffer;

typedef struct {
    unsigned int uiAlgID;
    unsigned int uiMode;
    unsigned int uiPadding;
    unsigned int uiHashAlgID;
    unsigned int uiSecurityLevel;
    void *pExParams;
} Unif_AlgParams;

typedef struct {
    void *pPublicKey;
    unsigned char *pucID;
    unsigned int uiIDLength;
} CCM_HashExParams;

typedef struct {
    unsigned char *pucContext;
    unsigned int uiContextLen;
    unsigned int uiHashAlgID;
    unsigned int uiExpectHashDataLen;
    unsigned int uiRandomizeSigning;
} CCM_DilithiumSignParams;

typedef struct {
    unsigned char *pucContext;
    unsigned int uiContextLen;
    unsigned int uiHashAlgID;
    unsigned int uiExpectHashDataLen;
    void *pDilithiumPublicKey;
} CCM_DilithiumVerifyParams;

int CCM_AlgorithmName(unsigned int uiAlgID, char *out, size_t out_sz);

/* 1. Environment */
int CCM_Initialize(void *phContext);
int CCM_Finalize(void *hContext);
int CCM_GetVersion(char *szVersion, unsigned int *puiVersionLen);
int CCM_Login(void *hSessionHandle, const char *szUserName, const char *szPin);
int CCM_ChangePin(void *hSessionHandle, const char *szOldPin, const char *szNewPin);
int CCM_Logout(void *hSessionHandle);
int CCM_GetCapability(void *hSessionHandle, Unif_Buffer *pCapabilityOut);
int CCM_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);

/* 2. Crypto operations */
int CCM_Hash(void *hSessionHandle,
             const Unif_AlgParams *pAlgParams,
             const Unif_Buffer *pData,
             Unif_Buffer *pHash);
int CCM_HashInit(void *hSessionHandle,
                 const Unif_AlgParams *pAlgParams);
int CCM_HashUpdate(void *hSessionHandle,
                   const Unif_Buffer *pData);
int CCM_HashFinal(void *hSessionHandle,
                  Unif_Buffer *pHash);
int CCM_Mac(void *hSessionHandle,
            const Unif_AlgParams *pAlgParams,
            const Unif_KeyRef *pKey,
            const Unif_Buffer *pIV,
            const Unif_Buffer *pData,
            Unif_Buffer *pMac);
int CCM_SymEncrypt(void *hSessionHandle,
                   const Unif_AlgParams *pAlgParams,
                   const Unif_KeyRef *pKey,
                   const Unif_Buffer *pIV,
                   const Unif_Buffer *pData,
                   Unif_Buffer *pCipher);
int CCM_SymDecrypt(void *hSessionHandle,
                   const Unif_AlgParams *pAlgParams,
                   const Unif_KeyRef *pKey,
                   const Unif_Buffer *pIV,
                   const Unif_Buffer *pCipher,
                   Unif_Buffer *pData);
int CCM_AsymEncrypt(void *hSessionHandle,
                    const Unif_AlgParams *pAlgParams,
                    const Unif_KeyRef *pPublicKey,
                    const Unif_Buffer *pData,
                    Unif_Buffer *pCipher);
int CCM_AsymDecrypt(void *hSessionHandle,
                    const Unif_AlgParams *pAlgParams,
                    const Unif_KeyRef *pPrivateKey,
                    const Unif_Buffer *pCipher,
                    Unif_Buffer *pData);

/* 3. Key management */
int CCM_GenerateKeyPair(void *hSessionHandle,
                        const Unif_AlgParams *pAlgParams,
                        unsigned int uiKeyIndex,
                        Unif_KeyRef *pPublicKey,
                        Unif_KeyRef *pPrivateKey);
int CCM_GenerateSymKey(void *hSessionHandle,
                       const Unif_AlgParams *pAlgParams,
                       unsigned int uiKeyIndex,
                       Unif_KeyRef *pKey);
int CCM_ImportKey(void *hSessionHandle,
                  const Unif_AlgParams *pAlgParams,
                  const Unif_Buffer *pKeyBlob,
                  Unif_KeyRef *pKey);
int CCM_ExportPublicKey(void *hSessionHandle,
                        const Unif_KeyRef *pKey,
                        Unif_Buffer *pPublicKeyBlob);
int CCM_DestroyKey(void *hSessionHandle,
                   const Unif_KeyRef *pKey);
int CCM_GetKeyInfo(void *hSessionHandle,
                   const Unif_KeyRef *pKey,
                   Unif_Buffer *pKeyInfo);
int CCM_KemEncapsulate(void *hSessionHandle,
                       const Unif_AlgParams *pAlgParams,
                       const Unif_KeyRef *pPublicKey,
                       Unif_Buffer *pCipherText,
                       Unif_Buffer *pSharedSecret);
int CCM_KemDecapsulate(void *hSessionHandle,
                       const Unif_AlgParams *pAlgParams,
                       const Unif_KeyRef *pPrivateKey,
                       const Unif_Buffer *pCipherText,
                       Unif_Buffer *pSharedSecret);
int CCM_KeyAgreementInit(void *hSessionHandle,
                         const Unif_AlgParams *pAlgParams,
                         const Unif_KeyRef *pSelfPrivateKey,
                         const Unif_Buffer *pSelfID,
                         Unif_Buffer *pAgreementData,
                         Unif_KeyRef *pAgreementHandle);
int CCM_KeyAgreementComplete(void *hSessionHandle,
                             const Unif_AlgParams *pAlgParams,
                             const Unif_KeyRef *pAgreementOrPrivateKey,
                             const Unif_Buffer *pPeerData,
                             Unif_Buffer *pSelfData,
                             Unif_KeyRef *pSessionKey);
int CCM_HybridKeyAgreement(void *hSessionHandle,
                           const Unif_AlgParams *pAlgParams,
                           const Unif_KeyRef *pClassicKey,
                           const Unif_KeyRef *pPqcKey,
                           const Unif_Buffer *pPeerData,
                           Unif_Buffer *pTranscript,
                           Unif_KeyRef *pSessionKey);

/* 4. Digital signature */
int CCM_Sign(void *hSessionHandle,
             const Unif_AlgParams *pAlgParams,
             const Unif_KeyRef *pPrivateKey,
             const Unif_Buffer *pData,
             Unif_Buffer *pSignature);
int CCM_Verify(void *hSessionHandle,
               const Unif_AlgParams *pAlgParams,
               const Unif_KeyRef *pPublicKey,
               const Unif_Buffer *pData,
               const Unif_Buffer *pSignature);
int CCM_SignDigest(void *hSessionHandle,
                   const Unif_AlgParams *pAlgParams,
                   const Unif_KeyRef *pPrivateKey,
                   const Unif_Buffer *pDigest,
                   Unif_Buffer *pSignature);
int CCM_VerifyDigest(void *hSessionHandle,
                     const Unif_AlgParams *pAlgParams,
                     const Unif_KeyRef *pPublicKey,
                     const Unif_Buffer *pDigest,
                     const Unif_Buffer *pSignature);
int CCM_HybridSign(void *hSessionHandle,
                   const Unif_AlgParams *pAlgParams,
                   const Unif_KeyRef *pClassicPrivateKey,
                   const Unif_KeyRef *pPqcPrivateKey,
                   const Unif_Buffer *pData,
                   Unif_Buffer *pSignature);
int CCM_HybridVerify(void *hSessionHandle,
                     const Unif_AlgParams *pAlgParams,
                     const Unif_KeyRef *pClassicPublicKey,
                     const Unif_KeyRef *pPqcPublicKey,
                     const Unif_Buffer *pData,
                     const Unif_Buffer *pSignature);

#ifdef __cplusplus
}
#endif

#endif
