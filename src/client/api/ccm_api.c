#include "ccm.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    char request_id[64];
    char key_ref[512];
    char payload[1024];
    char aux_payload[1024];
    char device_hint[256];
    char preference[256];
    char sequence[1024];
} ccm_json_options_t;

static int copy_out(const char *value, char *out, size_t out_sz) {
    int n;
    if (out == NULL || out_sz == 0U) return CCM_ERR_INVALID_ARGUMENT;
    n = snprintf(out, out_sz, "%s", value);
    return (n < 0 || (size_t)n >= out_sz) ? CCM_ERR_BUFFER_TOO_SMALL : CCM_OK;
}

static int append_token(char *out, size_t out_sz, const char *name, unsigned long value) {
    size_t used = strlen(out);
    int n = snprintf(out + used, out_sz - used, "%s%s=%lu", used == 0U ? "" : ";", name, value);
    return (n < 0 || (size_t)n >= out_sz - used) ? CCM_ERR_BUFFER_TOO_SMALL : CCM_OK;
}

static int append_ptr(char *out, size_t out_sz, const char *name, const void *ptr) {
    size_t used = strlen(out);
    int n = snprintf(out + used, out_sz - used, "%s%s=%p", used == 0U ? "" : ";", name, ptr);
    return (n < 0 || (size_t)n >= out_sz - used) ? CCM_ERR_BUFFER_TOO_SMALL : CCM_OK;
}

int CCM_AlgorithmName(unsigned int uiAlgID, char *out, size_t out_sz) {
    const char *name = NULL;
    switch ((ccm_algorithm_id_t)uiAlgID) {
        case CCM_ALG_AUTO: name = "auto"; break;
        case CCM_ALG_SM2:
        case CCM_ALG_SM2_SIGN:
        case CCM_ALG_SM2_ENC: name = "sm2"; break;
        case CCM_ALG_RSA:
        case CCM_ALG_RSA_SIGN:
        case CCM_ALG_RSA_ENC: name = "rsa"; break;
        case CCM_ALG_SM3: name = "sm3"; break;
        case CCM_ALG_SHA256: name = "sha256"; break;
        case CCM_ALG_SM4_CBC: name = "sm4-cbc"; break;
        case CCM_ALG_SM4_ECB: name = "sm4-ecb"; break;
        case CCM_ALG_SM4_MAC: name = "sm4-mac"; break;
        case CCM_ALG_AES_CBC: name = "aes-cbc"; break;
        case CCM_ALG_AES_ECB: name = "aes-ecb"; break;
        case CCM_ALG_KYBER512: name = "kyber512"; break;
        case CCM_ALG_KYBER768: name = "kyber768"; break;
        case CCM_ALG_KYBER1024: name = "kyber1024"; break;
        case CCM_ALG_MLKEM768: name = "mlkem768"; break;
        case CCM_ALG_DILITHIUM2: name = "dilithium2"; break;
        case CCM_ALG_DILITHIUM3: name = "dilithium3"; break;
        case CCM_ALG_DILITHIUM5: name = "dilithium5"; break;
        case CCM_ALG_SM9: name = "sm9"; break;
        default: return CCM_ERR_UNSUPPORTED_ALGORITHM;
    }
    return copy_out(name, out, out_sz);
}

static void init_opts(ccm_json_options_t *opts, const char *request_id) {
    memset(opts, 0, sizeof(*opts));
    snprintf(opts->request_id, sizeof(opts->request_id), "%s", request_id);
}

static int append_raw(char *out, size_t out_sz, size_t *pos, const char *s) {
    int n = snprintf(out + *pos, out_sz - *pos, "%s", s);
    if (n < 0 || (size_t)n >= out_sz - *pos) return CCM_ERR_BUFFER_TOO_SMALL;
    *pos += (size_t)n;
    return CCM_OK;
}

static int append_json_string(char *out, size_t out_sz, size_t *pos, const char *value) {
    const unsigned char *p = (const unsigned char *)(value == NULL ? "" : value);
    while (*p != '\0') {
        char tmp[8];
        if (*p == '"' || *p == '\\') { tmp[0] = '\\'; tmp[1] = (char)*p; tmp[2] = '\0'; }
        else if (*p == '\n') { tmp[0] = '\\'; tmp[1] = 'n'; tmp[2] = '\0'; }
        else if (*p == '\r') { tmp[0] = '\\'; tmp[1] = 'r'; tmp[2] = '\0'; }
        else if (*p == '\t') { tmp[0] = '\\'; tmp[1] = 't'; tmp[2] = '\0'; }
        else if (*p < 0x20U) {
            int n = snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned int)*p);
            if (n < 0 || (size_t)n >= sizeof(tmp)) return CCM_ERR_BUFFER_TOO_SMALL;
        } else { tmp[0] = (char)*p; tmp[1] = '\0'; }
        if (append_raw(out, out_sz, pos, tmp) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
        p++;
    }
    return CCM_OK;
}

static int append_field(char *out, size_t out_sz, size_t *pos, const char *name, const char *value, int comma) {
    if (append_raw(out, out_sz, pos, comma ? ",\"" : "\"") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_raw(out, out_sz, pos, name) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_raw(out, out_sz, pos, "\":\"") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_json_string(out, out_sz, pos, value) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_raw(out, out_sz, pos, "\"") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    return CCM_OK;
}

static int build_json(const char *domain, const char *action, unsigned int uiAlgID, const ccm_json_options_t *opts, char *out, size_t out_sz) {
    char algorithm[64];
    size_t pos = 0U;
    unsigned int alg = uiAlgID == 0U ? (unsigned int)CCM_ALG_AUTO : uiAlgID;
    if (domain == NULL || action == NULL || opts == NULL || out == NULL || out_sz == 0U || opts->request_id[0] == '\0') return CCM_ERR_INVALID_ARGUMENT;
    if (CCM_AlgorithmName(alg, algorithm, sizeof(algorithm)) != CCM_OK) return CCM_ERR_UNSUPPORTED_ALGORITHM;
    if (append_raw(out, out_sz, &pos, "{") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_field(out, out_sz, &pos, "request_id", opts->request_id, 0) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_field(out, out_sz, &pos, "domain", domain, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_field(out, out_sz, &pos, "action", action, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_field(out, out_sz, &pos, "algorithm", algorithm, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->key_ref[0] && append_field(out, out_sz, &pos, "key_ref", opts->key_ref, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->payload[0] && append_field(out, out_sz, &pos, "payload", opts->payload, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->aux_payload[0] && append_field(out, out_sz, &pos, "aux_payload", opts->aux_payload, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->device_hint[0] && append_field(out, out_sz, &pos, "device_hint", opts->device_hint, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->preference[0] && append_field(out, out_sz, &pos, "preference", opts->preference, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->sequence[0] && append_field(out, out_sz, &pos, "sequence", opts->sequence, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_raw(out, out_sz, &pos, "}\n") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    return CCM_OK;
}

static unsigned int alg_or_auto(const Unif_AlgParams *pAlgParams) {
    return pAlgParams == NULL || pAlgParams->uiAlgID == 0U ? (unsigned int)CCM_ALG_AUTO : pAlgParams->uiAlgID;
}

static int append_alg_params(char *payload, size_t payload_sz, const Unif_AlgParams *pAlgParams) {
    if (pAlgParams == NULL) return CCM_ERR_INVALID_ARGUMENT;
    if (append_token(payload, payload_sz, "mode", pAlgParams->uiMode) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(payload, payload_sz, "padding", pAlgParams->uiPadding) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(payload, payload_sz, "hash_alg", pAlgParams->uiHashAlgID) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(payload, payload_sz, "security_level", pAlgParams->uiSecurityLevel) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_ptr(payload, payload_sz, "ex_params", pAlgParams->pExParams) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    return CCM_OK;
}

static int append_key_ref(char *key_ref, size_t key_ref_sz, const Unif_KeyRef *pKey) {
    if (pKey == NULL) return CCM_ERR_INVALID_ARGUMENT;
    if (append_token(key_ref, key_ref_sz, "alg", pKey->uiAlgID) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(key_ref, key_ref_sz, "usage", pKey->uiUsage) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(key_ref, key_ref_sz, "source", pKey->uiSource) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(key_ref, key_ref_sz, "key_index", pKey->uiKeyIndex) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_ptr(key_ref, key_ref_sz, "key_handle", pKey->hKeyHandle) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_ptr(key_ref, key_ref_sz, "external_key", pKey->pExternalKey) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (pKey->szKeyId[0] != '\0') {
        if (append_raw(key_ref, key_ref_sz, &((size_t){strlen(key_ref)}), key_ref[0] ? ";key_id=" : "key_id=") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
        if (append_raw(key_ref, key_ref_sz, &((size_t){strlen(key_ref)}), pKey->szKeyId) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    }
    if (pKey->szDeviceId[0] != '\0') {
        if (append_raw(key_ref, key_ref_sz, &((size_t){strlen(key_ref)}), key_ref[0] ? ";device_id=" : "device_id=") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
        if (append_raw(key_ref, key_ref_sz, &((size_t){strlen(key_ref)}), pKey->szDeviceId) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    }
    return CCM_OK;
}

static int append_buffer(char *payload, size_t payload_sz, const char *name, const Unif_Buffer *buf) {
    if (buf == NULL) return CCM_ERR_INVALID_ARGUMENT;
    if (append_ptr(payload, payload_sz, name, buf->pucData) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_token(payload, payload_sz, "len", buf->uiDataLen) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    return CCM_OK;
}

static int route_buffered(const char *request_id,
                          const char *domain,
                          const char *action,
                          const Unif_AlgParams *pAlgParams,
                          const Unif_KeyRef *pKey,
                          const Unif_Buffer *pPrimary,
                          const Unif_Buffer *pAuxIn,
                          Unif_Buffer *pOutput) {
    ccm_json_options_t o;
    char json[2048];
    init_opts(&o, request_id);
    if (pAlgParams != NULL && append_alg_params(o.payload, sizeof(o.payload), pAlgParams) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (pKey != NULL && append_key_ref(o.key_ref, sizeof(o.key_ref), pKey) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (pPrimary != NULL && append_buffer(o.payload, sizeof(o.payload), "data", pPrimary) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (pAuxIn != NULL && append_buffer(o.aux_payload, sizeof(o.aux_payload), "aux", pAuxIn) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (pOutput != NULL && append_buffer(o.aux_payload, sizeof(o.aux_payload), "out", pOutput) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    return build_json(domain, action, alg_or_auto(pAlgParams), &o, json, sizeof(json));
}

int CCM_Initialize(void *phContext) { if (phContext != NULL) *(void **)phContext = phContext; return CCM_OK; }
int CCM_Finalize(void *hContext) { (void)hContext; return CCM_OK; }
int CCM_GetVersion(char *szVersion, unsigned int *puiVersionLen) { const char *v = "ccm-unified-api/2-four-categories"; if (szVersion == NULL || puiVersionLen == NULL) return CCM_ERR_INVALID_ARGUMENT; if (*puiVersionLen <= strlen(v)) { *puiVersionLen = (unsigned int)strlen(v) + 1U; return CCM_ERR_BUFFER_TOO_SMALL; } memcpy(szVersion, v, strlen(v) + 1U); *puiVersionLen = (unsigned int)strlen(v); return CCM_OK; }
int CCM_Login(void *hSessionHandle, const char *szUserName, const char *szPin) { (void)hSessionHandle; (void)szUserName; return szPin == NULL ? CCM_ERR_INVALID_ARGUMENT : CCM_OK; }
int CCM_ChangePin(void *hSessionHandle, const char *szOldPin, const char *szNewPin) { (void)hSessionHandle; return szOldPin == NULL || szNewPin == NULL ? CCM_ERR_INVALID_ARGUMENT : CCM_OK; }
int CCM_Logout(void *hSessionHandle) { (void)hSessionHandle; return CCM_OK; }
int CCM_GetCapability(void *hSessionHandle, Unif_Buffer *pCapabilityOut) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-capability"); if (pCapabilityOut == NULL) return CCM_ERR_INVALID_ARGUMENT; append_buffer(o.aux_payload, sizeof(o.aux_payload), "capability", pCapabilityOut); return build_json("device", "get_device_info", CCM_ALG_AUTO, &o, json, sizeof(json)); }
int CCM_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-random"); if (pucRandom == NULL && uiLength != 0U) return CCM_ERR_INVALID_ARGUMENT; append_token(o.payload, sizeof(o.payload), "length", uiLength); append_ptr(o.aux_payload, sizeof(o.aux_payload), "random", pucRandom); return build_json("device", "generate_random", CCM_ALG_AUTO, &o, json, sizeof(json)); }

int CCM_Hash(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_Buffer *pData, Unif_Buffer *pHash) { (void)hSessionHandle; return route_buffered("ccm-hash", "hash", "hash", pAlgParams, NULL, pData, NULL, pHash); }
int CCM_HashInit(void *hSessionHandle, const Unif_AlgParams *pAlgParams) { (void)hSessionHandle; return route_buffered("ccm-hash-init", "hash", "hash", pAlgParams, NULL, NULL, NULL, NULL); }
int CCM_HashUpdate(void *hSessionHandle, const Unif_Buffer *pData) { (void)hSessionHandle; Unif_AlgParams alg = { CCM_ALG_AUTO, 0U, 0U, 0U, 0U, NULL }; return route_buffered("ccm-hash-update", "hash", "hash", &alg, NULL, pData, NULL, NULL); }
int CCM_HashFinal(void *hSessionHandle, Unif_Buffer *pHash) { (void)hSessionHandle; Unif_AlgParams alg = { CCM_ALG_AUTO, 0U, 0U, 0U, 0U, NULL }; return route_buffered("ccm-hash-final", "hash", "hash", &alg, NULL, NULL, NULL, pHash); }
int CCM_Mac(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pKey, const Unif_Buffer *pIV, const Unif_Buffer *pData, Unif_Buffer *pMac) { (void)hSessionHandle; return route_buffered("ccm-mac", "sym", "mac", pAlgParams, pKey, pData, pIV, pMac); }
int CCM_SymEncrypt(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pKey, const Unif_Buffer *pIV, const Unif_Buffer *pData, Unif_Buffer *pCipher) { (void)hSessionHandle; return route_buffered("ccm-sym-enc", "sym", "encrypt", pAlgParams, pKey, pData, pIV, pCipher); }
int CCM_SymDecrypt(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pKey, const Unif_Buffer *pIV, const Unif_Buffer *pCipher, Unif_Buffer *pData) { (void)hSessionHandle; return route_buffered("ccm-sym-dec", "sym", "decrypt", pAlgParams, pKey, pCipher, pIV, pData); }
int CCM_AsymEncrypt(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPublicKey, const Unif_Buffer *pData, Unif_Buffer *pCipher) { (void)hSessionHandle; return route_buffered("ccm-asym-enc", "asym", "encrypt", pAlgParams, pPublicKey, pData, NULL, pCipher); }
int CCM_AsymDecrypt(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPrivateKey, const Unif_Buffer *pCipher, Unif_Buffer *pData) { (void)hSessionHandle; return route_buffered("ccm-asym-dec", "asym", "decrypt", pAlgParams, pPrivateKey, pCipher, NULL, pData); }

int CCM_GenerateKeyPair(void *hSessionHandle, const Unif_AlgParams *pAlgParams, unsigned int uiKeyIndex, Unif_KeyRef *pPublicKey, Unif_KeyRef *pPrivateKey) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-keypair"); if (pAlgParams == NULL || pPublicKey == NULL || pPrivateKey == NULL) return CCM_ERR_INVALID_ARGUMENT; append_alg_params(o.payload, sizeof(o.payload), pAlgParams); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_key_ref(o.aux_payload, sizeof(o.aux_payload), pPublicKey); append_key_ref(o.aux_payload, sizeof(o.aux_payload), pPrivateKey); return build_json("key", "generate_key_pair", alg_or_auto(pAlgParams), &o, json, sizeof(json)); }
int CCM_GenerateSymKey(void *hSessionHandle, const Unif_AlgParams *pAlgParams, unsigned int uiKeyIndex, Unif_KeyRef *pKey) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-sym-key"); if (pAlgParams == NULL || pKey == NULL) return CCM_ERR_INVALID_ARGUMENT; append_alg_params(o.payload, sizeof(o.payload), pAlgParams); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_key_ref(o.aux_payload, sizeof(o.aux_payload), pKey); return build_json("key", "import_key", alg_or_auto(pAlgParams), &o, json, sizeof(json)); }
int CCM_ImportKey(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_Buffer *pKeyBlob, Unif_KeyRef *pKey) { (void)hSessionHandle; return route_buffered("ccm-import-key", "key", "import_key", pAlgParams, pKey, pKeyBlob, NULL, NULL); }
int CCM_ExportPublicKey(void *hSessionHandle, const Unif_KeyRef *pKey, Unif_Buffer *pPublicKeyBlob) { (void)hSessionHandle; Unif_AlgParams alg = { pKey == NULL ? 0U : pKey->uiAlgID, 0U, 0U, 0U, 0U, NULL }; return route_buffered("ccm-export-pub", "key", "export_public_key", &alg, pKey, NULL, NULL, pPublicKeyBlob); }
int CCM_DestroyKey(void *hSessionHandle, const Unif_KeyRef *pKey) { (void)hSessionHandle; Unif_AlgParams alg = { pKey == NULL ? 0U : pKey->uiAlgID, 0U, 0U, 0U, 0U, NULL }; return route_buffered("ccm-destroy-key", "key", "destroy_key", &alg, pKey, NULL, NULL, NULL); }
int CCM_GetKeyInfo(void *hSessionHandle, const Unif_KeyRef *pKey, Unif_Buffer *pKeyInfo) { (void)hSessionHandle; Unif_AlgParams alg = { pKey == NULL ? 0U : pKey->uiAlgID, 0U, 0U, 0U, 0U, NULL }; return route_buffered("ccm-key-info", "key", "export_public_key", &alg, pKey, NULL, NULL, pKeyInfo); }
int CCM_KemEncapsulate(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPublicKey, Unif_Buffer *pCipherText, Unif_Buffer *pSharedSecret) { (void)hSessionHandle; return route_buffered("ccm-kem-encap", "pqc", "kem_encap", pAlgParams, pPublicKey, NULL, pCipherText, pSharedSecret); }
int CCM_KemDecapsulate(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPrivateKey, const Unif_Buffer *pCipherText, Unif_Buffer *pSharedSecret) { (void)hSessionHandle; return route_buffered("ccm-kem-decap", "pqc", "kem_decap", pAlgParams, pPrivateKey, pCipherText, NULL, pSharedSecret); }
int CCM_KeyAgreementInit(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pSelfPrivateKey, const Unif_Buffer *pSelfID, Unif_Buffer *pAgreementData, Unif_KeyRef *pAgreementHandle) {
    ccm_json_options_t o;
    char json[2048];
    (void)hSessionHandle;
    init_opts(&o, "ccm-agree-init");
    if (pAlgParams == NULL || pSelfPrivateKey == NULL || pSelfID == NULL || pAgreementData == NULL || pAgreementHandle == NULL) return CCM_ERR_INVALID_ARGUMENT;
    append_alg_params(o.payload, sizeof(o.payload), pAlgParams);
    append_key_ref(o.key_ref, sizeof(o.key_ref), pSelfPrivateKey);
    append_buffer(o.payload, sizeof(o.payload), "self_id", pSelfID);
    append_buffer(o.aux_payload, sizeof(o.aux_payload), "agreement_data", pAgreementData);
    append_key_ref(o.aux_payload, sizeof(o.aux_payload), pAgreementHandle);
    return build_json("key", "generate_key_pair", alg_or_auto(pAlgParams), &o, json, sizeof(json));
}
int CCM_KeyAgreementComplete(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pAgreementOrPrivateKey, const Unif_Buffer *pPeerData, Unif_Buffer *pSelfData, Unif_KeyRef *pSessionKey) {
    ccm_json_options_t o;
    char json[2048];
    (void)hSessionHandle;
    init_opts(&o, "ccm-agree-complete");
    if (pAlgParams == NULL || pAgreementOrPrivateKey == NULL || pPeerData == NULL || pSelfData == NULL || pSessionKey == NULL) return CCM_ERR_INVALID_ARGUMENT;
    append_alg_params(o.payload, sizeof(o.payload), pAlgParams);
    append_key_ref(o.key_ref, sizeof(o.key_ref), pAgreementOrPrivateKey);
    append_buffer(o.payload, sizeof(o.payload), "peer_data", pPeerData);
    append_buffer(o.aux_payload, sizeof(o.aux_payload), "self_data", pSelfData);
    append_key_ref(o.aux_payload, sizeof(o.aux_payload), pSessionKey);
    return build_json("key", "import_key", alg_or_auto(pAlgParams), &o, json, sizeof(json));
}
int CCM_HybridKeyAgreement(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pClassicKey, const Unif_KeyRef *pPqcKey, const Unif_Buffer *pPeerData, Unif_Buffer *pTranscript, Unif_KeyRef *pSessionKey) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-hybrid-agree"); if (pAlgParams == NULL || pClassicKey == NULL || pPqcKey == NULL || pSessionKey == NULL) return CCM_ERR_INVALID_ARGUMENT; append_alg_params(o.payload, sizeof(o.payload), pAlgParams); append_key_ref(o.key_ref, sizeof(o.key_ref), pClassicKey); append_key_ref(o.key_ref, sizeof(o.key_ref), pPqcKey); if (pPeerData != NULL) append_buffer(o.payload, sizeof(o.payload), "peer", pPeerData); if (pTranscript != NULL) append_buffer(o.aux_payload, sizeof(o.aux_payload), "transcript", pTranscript); append_key_ref(o.aux_payload, sizeof(o.aux_payload), pSessionKey); return build_json("pqc", "kem_encap", alg_or_auto(pAlgParams), &o, json, sizeof(json)); }

int CCM_Sign(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPrivateKey, const Unif_Buffer *pData, Unif_Buffer *pSignature) { (void)hSessionHandle; const char *domain = alg_or_auto(pAlgParams) == CCM_ALG_DILITHIUM2 || alg_or_auto(pAlgParams) == CCM_ALG_DILITHIUM3 || alg_or_auto(pAlgParams) == CCM_ALG_DILITHIUM5 ? "pqc" : "asym"; return route_buffered("ccm-sign", domain, "sign", pAlgParams, pPrivateKey, pData, NULL, pSignature); }
int CCM_Verify(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPublicKey, const Unif_Buffer *pData, const Unif_Buffer *pSignature) { (void)hSessionHandle; const char *domain = alg_or_auto(pAlgParams) == CCM_ALG_DILITHIUM2 || alg_or_auto(pAlgParams) == CCM_ALG_DILITHIUM3 || alg_or_auto(pAlgParams) == CCM_ALG_DILITHIUM5 ? "pqc" : "asym"; return route_buffered("ccm-verify", domain, "verify", pAlgParams, pPublicKey, pData, pSignature, NULL); }
int CCM_SignDigest(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPrivateKey, const Unif_Buffer *pDigest, Unif_Buffer *pSignature) { return CCM_Sign(hSessionHandle, pAlgParams, pPrivateKey, pDigest, pSignature); }
int CCM_VerifyDigest(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pPublicKey, const Unif_Buffer *pDigest, const Unif_Buffer *pSignature) { return CCM_Verify(hSessionHandle, pAlgParams, pPublicKey, pDigest, pSignature); }
int CCM_HybridSign(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pClassicPrivateKey, const Unif_KeyRef *pPqcPrivateKey, const Unif_Buffer *pData, Unif_Buffer *pSignature) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-hybrid-sign"); if (pAlgParams == NULL || pClassicPrivateKey == NULL || pPqcPrivateKey == NULL || pData == NULL || pSignature == NULL) return CCM_ERR_INVALID_ARGUMENT; append_alg_params(o.payload, sizeof(o.payload), pAlgParams); append_key_ref(o.key_ref, sizeof(o.key_ref), pClassicPrivateKey); append_key_ref(o.key_ref, sizeof(o.key_ref), pPqcPrivateKey); append_buffer(o.payload, sizeof(o.payload), "data", pData); append_buffer(o.aux_payload, sizeof(o.aux_payload), "signature", pSignature); snprintf(o.sequence, sizeof(o.sequence), "asym:sign:classic:sm2>pqc:sign:pqc:dilithium3"); return build_json("asym", "sign", alg_or_auto(pAlgParams), &o, json, sizeof(json)); }
int CCM_HybridVerify(void *hSessionHandle, const Unif_AlgParams *pAlgParams, const Unif_KeyRef *pClassicPublicKey, const Unif_KeyRef *pPqcPublicKey, const Unif_Buffer *pData, const Unif_Buffer *pSignature) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, "ccm-hybrid-verify"); if (pAlgParams == NULL || pClassicPublicKey == NULL || pPqcPublicKey == NULL || pData == NULL || pSignature == NULL) return CCM_ERR_INVALID_ARGUMENT; append_alg_params(o.payload, sizeof(o.payload), pAlgParams); append_key_ref(o.key_ref, sizeof(o.key_ref), pClassicPublicKey); append_key_ref(o.key_ref, sizeof(o.key_ref), pPqcPublicKey); append_buffer(o.payload, sizeof(o.payload), "data", pData); append_buffer(o.aux_payload, sizeof(o.aux_payload), "signature", pSignature); snprintf(o.sequence, sizeof(o.sequence), "asym:verify:classic:sm2>pqc:verify:pqc:dilithium3"); return build_json("asym", "verify", alg_or_auto(pAlgParams), &o, json, sizeof(json)); }
