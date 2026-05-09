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
 * CCM 上层统一接口。
 * 约束：能用算法 ID 表达的差异全部用 uiAlgID，不再拆 RsaSign/Sm2Sign/SM9Sign 这类算法名函数。
 * 这些函数负责把完整上层参数归一化到既有 JSON API；底层真实能力由现有 JSON API/adapter 保证。
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

typedef struct {
    unsigned int uiSecondaryAlgID;
    unsigned int uiSecondaryKeyIndex;
    void *pSecondaryExternalKey;
} CCM_HybridExParams;

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

typedef struct {
    void *pPublicKey;
    unsigned char *pucID;
    unsigned int uiIDLength;
} CCM_HashExParams;

int CCM_AlgorithmName(unsigned int uiAlgID, char *out, size_t out_sz);

/* 环境类函数 */
int CCM_Initialize(void *phContext);
int CCM_Finalize(void *hContext);
int CCM_GetVersion(char *szVersion, unsigned int *puiVersionLen);
int CCM_Login(void *hSessionHandle, const char *szUserName, const char *szPin);
int CCM_ChangePin(void *hSessionHandle, const char *szOldPin, const char *szNewPin);
int CCM_Logout(void *hSessionHandle);

/* 证书类函数：证书类型、来源、索引等差异放入参数，不再按 Root/CA/LDAP/OCSP 拆散主接口。 */
int CCM_AddCertificate(void *hSessionHandle,
                       unsigned int uiCertType,
                       unsigned char *pucCert,
                       unsigned int uiCertLen);
int CCM_GetCertificateCount(void *hSessionHandle,
                            unsigned int uiCertType,
                            unsigned int *puiCount);
int CCM_GetCertificate(void *hSessionHandle,
                       unsigned int uiCertType,
                       unsigned int uiCertIndex,
                       unsigned char *pucCert,
                       unsigned int *puiCertLen);
int CCM_RemoveCertificate(void *hSessionHandle,
                          unsigned int uiCertType,
                          unsigned int uiCertIndex);
int CCM_AddCrl(void *hSessionHandle,
               unsigned char *pucCrl,
               unsigned int uiCrlLen);
int CCM_VerifyCertificate(void *hSessionHandle,
                          unsigned int uiAlgID,
                          unsigned char *pucCert,
                          unsigned int uiCertLen,
                          unsigned char *pucTrustOrCrl,
                          unsigned int uiTrustOrCrlLen,
                          void *pExParams);
int CCM_GetCertificateState(void *hSessionHandle,
                            unsigned int uiQueryType,
                            unsigned char *pucCert,
                            unsigned int uiCertLen,
                            unsigned int *puiState,
                            void *pExParams);
int CCM_FetchCertificate(void *hSessionHandle,
                         const char *szUri,
                         unsigned char *pucCert,
                         unsigned int *puiCertLen);
int CCM_FetchCrl(void *hSessionHandle,
                 const char *szUri,
                 unsigned char *pucCrl,
                 unsigned int *puiCrlLen);
int CCM_GetCertificateInfo(void *hSessionHandle,
                           unsigned int uiInfoType,
                           unsigned char *pucCert,
                           unsigned int uiCertLen,
                           unsigned char *pucInfo,
                           unsigned int *puiInfoLen);
int CCM_EnumCertificates(void *hSessionHandle,
                         unsigned int uiCertType,
                         unsigned char *pucOut,
                         unsigned int *puiOutLen);
int CCM_EnumKeyContainers(void *hSessionHandle,
                          unsigned char *pucOut,
                          unsigned int *puiOutLen);

/* 密码运算类函数 */
int CCM_Base64Encode(unsigned char *pucData,
                     unsigned int uiDataLen,
                     unsigned char *pucOut,
                     unsigned int *puiOutLen);
int CCM_Base64Decode(unsigned char *pucData,
                     unsigned int uiDataLen,
                     unsigned char *pucOut,
                     unsigned int *puiOutLen);
int CCM_GenerateRandom(void *hSessionHandle,
                       unsigned int uiLength,
                       unsigned char *pucRandom);
int CCM_GenerateKeyPair(void *hSessionHandle,
                        unsigned int uiAlgID,
                        unsigned int uiKeyConfig,
                        unsigned int uiKeyIndex,
                        void *pPublicKey,
                        void *pPrivateKey);
int CCM_Sign(void *hSessionHandle,
             unsigned int uiAlgID,
             unsigned int uiKeyIndex,
             void *pExternalKey,
             unsigned int uiKeyUsage,
             unsigned char *pucData,
             unsigned int uiDataLen,
             void *pSignature,
             unsigned int *puiSigLen,
             void *pExParams);
int CCM_Verify(void *hSessionHandle,
               unsigned int uiAlgID,
               unsigned int uiKeyIndex,
               void *pExternalKey,
               unsigned int uiKeyUsage,
               unsigned char *pucData,
               unsigned int uiDataLen,
               void *pSignature,
               unsigned int uiSigLen,
               void *pExParams);
int CCM_SymEncrypt(void *hSessionHandle,
                   unsigned int uiAlgID,
                   unsigned int uiKeyIndex,
                   void *hKeyHandle,
                   unsigned char *pucIV,
                   unsigned char *pucData,
                   unsigned int uiDataLen,
                   unsigned char *pucEncData,
                   unsigned int *puiEncDataLen);
int CCM_SymDecrypt(void *hSessionHandle,
                   unsigned int uiAlgID,
                   unsigned int uiKeyIndex,
                   void *hKeyHandle,
                   unsigned char *pucIV,
                   unsigned char *pucEncData,
                   unsigned int uiEncDataLen,
                   unsigned char *pucData,
                   unsigned int *puiDataLen);
int CCM_AsymEncrypt(void *hSessionHandle,
                    unsigned int uiAlgID,
                    unsigned int uiKeyIndex,
                    void *pExternalKey,
                    unsigned char *pucData,
                    unsigned int uiDataLen,
                    void *pCipher,
                    unsigned int *puiCipherLen);
int CCM_AsymDecrypt(void *hSessionHandle,
                    unsigned int uiAlgID,
                    unsigned int uiKeyIndex,
                    void *pExternalKey,
                    void *pCipher,
                    unsigned int uiCipherLen,
                    unsigned char *pucData,
                    unsigned int *puiDataLen);
int CCM_KeyEncapsulate(void *hSessionHandle,
                       unsigned int uiAlgID,
                       unsigned int uiKeyIndex,
                       void *pPublicKey,
                       unsigned int uiSecurityLevel,
                       unsigned char *pucCipher,
                       unsigned int *puiCipherLen,
                       unsigned char *pucSharedKey,
                       unsigned int *puiSharedKeyLen);
int CCM_KeyDecapsulate(void *hSessionHandle,
                       unsigned int uiAlgID,
                       unsigned int uiKeyIndex,
                       void *pPrivateKey,
                       unsigned int uiSecurityLevel,
                       unsigned char *pucCipher,
                       unsigned int uiCipherLen,
                       unsigned char *pucSharedKey,
                       unsigned int *puiSharedKeyLen);
int CCM_GenerateAgreementData(void *hSessionHandle,
                              unsigned int uiISKIndex,
                              unsigned int uiKeyBits,
                              unsigned char *pucSponsorID,
                              unsigned int uiSponsorIDLen,
                              void *pSponsorPublicKey,
                              void *pSponsorTmpPublicKey,
                              void **phAgreementHandle);
int CCM_GenerateKeyAgreement(void *hSessionHandle,
                             unsigned int uiISKIndex,
                             unsigned int uiKeyBits,
                             unsigned char *pucPeerID,
                             unsigned int uiPeerIDLen,
                             void *pPeerPublicKey,
                             void *pPeerTmpPublicKey,
                             void *hAgreementHandle,
                             void *pSelfPublicKey,
                             void *pSelfTmpPublicKey,
                             void **phKeyHandle);
int CCM_HashInit(void *hSessionHandle,
                 unsigned int uiAlgID,
                 void *pExParams);
int CCM_HashUpdate(void *hSessionHandle,
                   unsigned char *pucData,
                   unsigned int uiDataLen);
int CCM_HashFinal(void *hSessionHandle,
                  unsigned char *pucHash,
                  unsigned int *puiHashLen);
int CCM_Mac(void *hSessionHandle,
            unsigned int uiAlgID,
            unsigned int uiKeyIndex,
            void *hKeyHandle,
            unsigned char *pucIV,
            unsigned char *pucData,
            unsigned int uiDataLen,
            unsigned char *pucMac,
            unsigned int *puiMacLen);
int CCM_HybridSign(void *hSessionHandle,
                   unsigned int uiMainAlgID,
                   unsigned int uiMainKeyIndex,
                   CCM_HybridExParams *pHybridParams,
                   unsigned char *pucData,
                   unsigned int uiDataLen,
                   unsigned char *pucSignature,
                   unsigned int *puiSigLen);
int CCM_HybridVerify(void *hSessionHandle,
                     unsigned int uiMainAlgID,
                     unsigned int uiMainKeyIndex,
                     void *pMainExternalKey,
                     CCM_HybridExParams *pHybridParams,
                     unsigned char *pucData,
                     unsigned int uiDataLen,
                     unsigned char *pucSignature,
                     unsigned int uiSigLen);
int CCM_HybridAgreement(void *hSessionHandle,
                        unsigned int uiAlgID_ECC,
                        unsigned int uiAlgID_PQC,
                        unsigned int uiISKIndex,
                        unsigned int uiKyberKeyIndex,
                        void *pPeerECCPubKey,
                        void *pPeerKyberPubKey,
                        unsigned char *pucKyberCipher,
                        void **phKeyHandle);

/* 消息类函数：PKCS7/CMS/SM2 消息语义集中到 message_type 与 algorithm_id。 */
int CCM_MessageEncode(unsigned int uiMessageType,
                      void *hSessionHandle,
                      unsigned int uiAlgID,
                      unsigned int uiKeyIndex,
                      void *pKeyOrCert,
                      unsigned char *pucData,
                      unsigned int uiDataLen,
                      unsigned char *pucMessage,
                      unsigned int *puiMessageLen,
                      void *pExParams);
int CCM_MessageDecode(unsigned int uiMessageType,
                      void *hSessionHandle,
                      unsigned int uiAlgID,
                      unsigned int uiKeyIndex,
                      void *pKeyOrCert,
                      unsigned char *pucMessage,
                      unsigned int uiMessageLen,
                      unsigned char *pucData,
                      unsigned int *puiDataLen,
                      void *pExParams);
int CCM_MessageParseSignedData(void *hSessionHandle,
                               unsigned char *pucSignedData,
                               unsigned int uiSignedDataLen,
                               unsigned char *pucInfo,
                               unsigned int *puiInfoLen);

#ifdef __cplusplus
}
#endif

#endif
