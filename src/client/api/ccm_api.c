#include "ccm.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    char request_id[64];
    char key_ref[256];
    char payload[1024];
    char aux_payload[1024];
    char user_pin[256];
    char device_hint[256];
    char preference[256];
    char sequence[1024];
} ccm_json_options_t;

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

static int copy_out(const char *value, char *out, size_t out_sz) {
    int n;
    if (out == NULL || out_sz == 0U) return CCM_ERR_INVALID_ARGUMENT;
    n = snprintf(out, out_sz, "%s", value);
    return (n < 0 || (size_t)n >= out_sz) ? CCM_ERR_BUFFER_TOO_SMALL : CCM_OK;
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
    if (opts->user_pin[0] && append_field(out, out_sz, &pos, "user_pin", opts->user_pin, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->device_hint[0] && append_field(out, out_sz, &pos, "device_hint", opts->device_hint, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->preference[0] && append_field(out, out_sz, &pos, "preference", opts->preference, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (opts->sequence[0] && append_field(out, out_sz, &pos, "sequence", opts->sequence, 1) != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    if (append_raw(out, out_sz, &pos, "}\n") != CCM_OK) return CCM_ERR_BUFFER_TOO_SMALL;
    return CCM_OK;
}

static int emit_json_to_buffer(const char *domain, const char *action, unsigned int uiAlgID, const ccm_json_options_t *opts, unsigned char *out, unsigned int *out_len) {
    int rc;
    char json[2048];
    if (out == NULL || out_len == NULL) return CCM_ERR_INVALID_ARGUMENT;
    rc = build_json(domain, action, uiAlgID, opts, json, sizeof(json));
    if (rc != CCM_OK) return rc;
    if (*out_len <= strlen(json)) { *out_len = (unsigned int)strlen(json) + 1U; return CCM_ERR_BUFFER_TOO_SMALL; }
    memcpy(out, json, strlen(json) + 1U);
    *out_len = (unsigned int)strlen(json);
    return CCM_OK;
}

static void init_opts(ccm_json_options_t *opts, const char *request_id) {
    memset(opts, 0, sizeof(*opts));
    snprintf(opts->request_id, sizeof(opts->request_id), "%s", request_id);
}

int CCM_Initialize(void *phContext) { if (phContext != NULL) *(void **)phContext = phContext; return CCM_OK; }
int CCM_Finalize(void *hContext) { (void)hContext; return CCM_OK; }
int CCM_GetVersion(char *szVersion, unsigned int *puiVersionLen) { const char *v = "ccm-unified-api/1"; if (szVersion == NULL || puiVersionLen == NULL) return CCM_ERR_INVALID_ARGUMENT; if (*puiVersionLen <= strlen(v)) { *puiVersionLen = (unsigned int)strlen(v) + 1U; return CCM_ERR_BUFFER_TOO_SMALL; } memcpy(szVersion, v, strlen(v) + 1U); *puiVersionLen = (unsigned int)strlen(v); return CCM_OK; }
int CCM_Login(void *hSessionHandle, const char *szUserName, const char *szPin) { (void)hSessionHandle; (void)szUserName; return (szPin == NULL) ? CCM_ERR_INVALID_ARGUMENT : CCM_OK; }
int CCM_ChangePin(void *hSessionHandle, const char *szOldPin, const char *szNewPin) { (void)hSessionHandle; return (szOldPin == NULL || szNewPin == NULL) ? CCM_ERR_INVALID_ARGUMENT : CCM_OK; }
int CCM_Logout(void *hSessionHandle) { (void)hSessionHandle; return CCM_OK; }

#define REQUEST_ID(name) "ccm-" name

int CCM_AddCertificate(void *hSessionHandle, unsigned int uiCertType, unsigned char *pucCert, unsigned int uiCertLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("add-cert")); append_token(o.key_ref, sizeof(o.key_ref), "cert_type", uiCertType); append_ptr(o.payload, sizeof(o.payload), "cert", pucCert); append_token(o.payload, sizeof(o.payload), "cert_len", uiCertLen); return (pucCert == NULL && uiCertLen != 0U) ? CCM_ERR_INVALID_ARGUMENT : CCM_OK; }
int CCM_GetCertificateCount(void *hSessionHandle, unsigned int uiCertType, unsigned int *puiCount) { (void)hSessionHandle; if (puiCount == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiCount = 0U; (void)uiCertType; return CCM_OK; }
int CCM_GetCertificate(void *hSessionHandle, unsigned int uiCertType, unsigned int uiCertIndex, unsigned char *pucCert, unsigned int *puiCertLen) { (void)hSessionHandle; (void)uiCertType; (void)uiCertIndex; if (pucCert == NULL || puiCertLen == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiCertLen = 0U; return CCM_OK; }
int CCM_RemoveCertificate(void *hSessionHandle, unsigned int uiCertType, unsigned int uiCertIndex) { (void)hSessionHandle; (void)uiCertType; (void)uiCertIndex; return CCM_OK; }
int CCM_AddCrl(void *hSessionHandle, unsigned char *pucCrl, unsigned int uiCrlLen) { (void)hSessionHandle; return (pucCrl == NULL && uiCrlLen != 0U) ? CCM_ERR_INVALID_ARGUMENT : CCM_OK; }
int CCM_VerifyCertificate(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucCert, unsigned int uiCertLen, unsigned char *pucTrustOrCrl, unsigned int uiTrustOrCrlLen, void *pExParams) { (void)hSessionHandle; (void)pExParams; ccm_json_options_t o; char json[2048]; init_opts(&o, REQUEST_ID("verify-cert")); append_ptr(o.payload, sizeof(o.payload), "cert", pucCert); append_token(o.payload, sizeof(o.payload), "cert_len", uiCertLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "trust_or_crl", pucTrustOrCrl); append_token(o.aux_payload, sizeof(o.aux_payload), "trust_or_crl_len", uiTrustOrCrlLen); return (pucCert == NULL || uiCertLen == 0U) ? CCM_ERR_INVALID_ARGUMENT : build_json("asym", "verify", uiAlgID, &o, json, sizeof(json)); }
int CCM_GetCertificateState(void *hSessionHandle, unsigned int uiQueryType, unsigned char *pucCert, unsigned int uiCertLen, unsigned int *puiState, void *pExParams) { (void)hSessionHandle; (void)uiQueryType; (void)pExParams; if (pucCert == NULL || uiCertLen == 0U || puiState == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiState = 0U; return CCM_OK; }
int CCM_FetchCertificate(void *hSessionHandle, const char *szUri, unsigned char *pucCert, unsigned int *puiCertLen) { (void)hSessionHandle; if (szUri == NULL || pucCert == NULL || puiCertLen == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiCertLen = 0U; return CCM_OK; }
int CCM_FetchCrl(void *hSessionHandle, const char *szUri, unsigned char *pucCrl, unsigned int *puiCrlLen) { (void)hSessionHandle; if (szUri == NULL || pucCrl == NULL || puiCrlLen == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiCrlLen = 0U; return CCM_OK; }
int CCM_GetCertificateInfo(void *hSessionHandle, unsigned int uiInfoType, unsigned char *pucCert, unsigned int uiCertLen, unsigned char *pucInfo, unsigned int *puiInfoLen) { (void)hSessionHandle; (void)uiInfoType; if (pucCert == NULL || uiCertLen == 0U || pucInfo == NULL || puiInfoLen == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiInfoLen = 0U; return CCM_OK; }
int CCM_EnumCertificates(void *hSessionHandle, unsigned int uiCertType, unsigned char *pucOut, unsigned int *puiOutLen) { (void)hSessionHandle; (void)uiCertType; if (pucOut == NULL || puiOutLen == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiOutLen = 0U; return CCM_OK; }
int CCM_EnumKeyContainers(void *hSessionHandle, unsigned char *pucOut, unsigned int *puiOutLen) { (void)hSessionHandle; if (pucOut == NULL || puiOutLen == NULL) return CCM_ERR_INVALID_ARGUMENT; *puiOutLen = 0U; return CCM_OK; }

int CCM_Base64Encode(unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucOut, unsigned int *puiOutLen) { ccm_json_options_t o; init_opts(&o, REQUEST_ID("base64-enc")); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); if (pucOut == NULL || puiOutLen == NULL) return CCM_ERR_INVALID_ARGUMENT; return emit_json_to_buffer("sym", "encrypt", CCM_ALG_AUTO, &o, pucOut, puiOutLen); }
int CCM_Base64Decode(unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucOut, unsigned int *puiOutLen) { ccm_json_options_t o; init_opts(&o, REQUEST_ID("base64-dec")); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); if (pucOut == NULL || puiOutLen == NULL) return CCM_ERR_INVALID_ARGUMENT; return emit_json_to_buffer("sym", "decrypt", CCM_ALG_AUTO, &o, pucOut, puiOutLen); }
int CCM_GenerateRandom(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; if (pucRandom == NULL && uiLength != 0U) return CCM_ERR_INVALID_ARGUMENT; init_opts(&o, REQUEST_ID("random")); append_token(o.payload, sizeof(o.payload), "length", uiLength); return build_json("device", "generate_random", CCM_ALG_AUTO, &o, json, sizeof(json)); }
int CCM_GenerateKeyPair(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyConfig, unsigned int uiKeyIndex, void *pPublicKey, void *pPrivateKey) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, REQUEST_ID("keypair")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_token(o.payload, sizeof(o.payload), "key_config", uiKeyConfig); append_ptr(o.payload, sizeof(o.payload), "public_key", pPublicKey); append_ptr(o.payload, sizeof(o.payload), "private_key", pPrivateKey); return build_json("key", "generate_key_pair", uiAlgID, &o, json, sizeof(json)); }
int CCM_Sign(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pExternalKey, unsigned int uiKeyUsage, unsigned char *pucData, unsigned int uiDataLen, void *pSignature, unsigned int *puiSigLen, void *pExParams) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, REQUEST_ID("sign")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_token(o.key_ref, sizeof(o.key_ref), "key_usage", uiKeyUsage); append_ptr(o.key_ref, sizeof(o.key_ref), "external_key", pExternalKey); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "signature", pSignature); append_ptr(o.aux_payload, sizeof(o.aux_payload), "sig_len", puiSigLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "ex_params", pExParams); return build_json("asym", "sign", uiAlgID, &o, json, sizeof(json)); }
int CCM_Verify(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pExternalKey, unsigned int uiKeyUsage, unsigned char *pucData, unsigned int uiDataLen, void *pSignature, unsigned int uiSigLen, void *pExParams) { (void)hSessionHandle; ccm_json_options_t o; char json[2048]; init_opts(&o, REQUEST_ID("verify")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_token(o.key_ref, sizeof(o.key_ref), "key_usage", uiKeyUsage); append_ptr(o.key_ref, sizeof(o.key_ref), "external_key", pExternalKey); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "signature", pSignature); append_token(o.aux_payload, sizeof(o.aux_payload), "sig_len", uiSigLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "ex_params", pExParams); return build_json("asym", "verify", uiAlgID, &o, json, sizeof(json)); }

#define DEFINE_JSON_ONLY(name, domain, action) \
    static int name(unsigned int uiAlgID, ccm_json_options_t *o) { char json[2048]; return build_json(domain, action, uiAlgID, o, json, sizeof(json)); }
DEFINE_JSON_ONLY(route_sym_encrypt, "sym", "encrypt")
DEFINE_JSON_ONLY(route_sym_decrypt, "sym", "decrypt")
DEFINE_JSON_ONLY(route_asym_encrypt, "asym", "encrypt")
DEFINE_JSON_ONLY(route_asym_decrypt, "asym", "decrypt")
DEFINE_JSON_ONLY(route_kem_encap, "pqc", "kem_encap")
DEFINE_JSON_ONLY(route_kem_decap, "pqc", "kem_decap")
DEFINE_JSON_ONLY(route_hash, "hash", "hash")
DEFINE_JSON_ONLY(route_mac, "sym", "mac")
#undef DEFINE_JSON_ONLY

int CCM_SymEncrypt(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *hKeyHandle, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucEncData, unsigned int *puiEncDataLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("sym-enc")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "key_handle", hKeyHandle); append_ptr(o.payload, sizeof(o.payload), "iv", pucIV); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "enc_data", pucEncData); append_ptr(o.aux_payload, sizeof(o.aux_payload), "enc_len", puiEncDataLen); return route_sym_encrypt(uiAlgID, &o); }
int CCM_SymDecrypt(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *hKeyHandle, unsigned char *pucIV, unsigned char *pucEncData, unsigned int uiEncDataLen, unsigned char *pucData, unsigned int *puiDataLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("sym-dec")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "key_handle", hKeyHandle); append_ptr(o.payload, sizeof(o.payload), "iv", pucIV); append_ptr(o.payload, sizeof(o.payload), "enc_data", pucEncData); append_token(o.payload, sizeof(o.payload), "enc_len", uiEncDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "data", pucData); append_ptr(o.aux_payload, sizeof(o.aux_payload), "data_len", puiDataLen); return route_sym_decrypt(uiAlgID, &o); }
int CCM_AsymEncrypt(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pExternalKey, unsigned char *pucData, unsigned int uiDataLen, void *pCipher, unsigned int *puiCipherLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("asym-enc")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "external_key", pExternalKey); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "cipher", pCipher); append_ptr(o.aux_payload, sizeof(o.aux_payload), "cipher_len", puiCipherLen); return route_asym_encrypt(uiAlgID, &o); }
int CCM_AsymDecrypt(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pExternalKey, void *pCipher, unsigned int uiCipherLen, unsigned char *pucData, unsigned int *puiDataLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("asym-dec")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "external_key", pExternalKey); append_ptr(o.payload, sizeof(o.payload), "cipher", pCipher); append_token(o.payload, sizeof(o.payload), "cipher_len", uiCipherLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "data", pucData); append_ptr(o.aux_payload, sizeof(o.aux_payload), "data_len", puiDataLen); return route_asym_decrypt(uiAlgID, &o); }
int CCM_KeyEncapsulate(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pPublicKey, unsigned int uiSecurityLevel, unsigned char *pucCipher, unsigned int *puiCipherLen, unsigned char *pucSharedKey, unsigned int *puiSharedKeyLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("kem-encap")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "public_key", pPublicKey); append_token(o.payload, sizeof(o.payload), "security_level", uiSecurityLevel); append_ptr(o.aux_payload, sizeof(o.aux_payload), "cipher", pucCipher); append_ptr(o.aux_payload, sizeof(o.aux_payload), "cipher_len", puiCipherLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "shared_key", pucSharedKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "shared_key_len", puiSharedKeyLen); return route_kem_encap(uiAlgID, &o); }
int CCM_KeyDecapsulate(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pPrivateKey, unsigned int uiSecurityLevel, unsigned char *pucCipher, unsigned int uiCipherLen, unsigned char *pucSharedKey, unsigned int *puiSharedKeyLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("kem-decap")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "private_key", pPrivateKey); append_token(o.payload, sizeof(o.payload), "security_level", uiSecurityLevel); append_ptr(o.payload, sizeof(o.payload), "cipher", pucCipher); append_token(o.payload, sizeof(o.payload), "cipher_len", uiCipherLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "shared_key", pucSharedKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "shared_key_len", puiSharedKeyLen); return route_kem_decap(uiAlgID, &o); }
int CCM_GenerateAgreementData(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID, unsigned int uiSponsorIDLen, void *pSponsorPublicKey, void *pSponsorTmpPublicKey, void **phAgreementHandle) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("agreement-data")); append_token(o.key_ref, sizeof(o.key_ref), "isk_index", uiISKIndex); append_token(o.payload, sizeof(o.payload), "key_bits", uiKeyBits); append_ptr(o.payload, sizeof(o.payload), "sponsor_id", pucSponsorID); append_token(o.payload, sizeof(o.payload), "sponsor_id_len", uiSponsorIDLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "sponsor_pub", pSponsorPublicKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "sponsor_tmp_pub", pSponsorTmpPublicKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "agreement_handle", phAgreementHandle); return route_sym_encrypt(CCM_ALG_SM2, &o); }
int CCM_GenerateKeyAgreement(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucPeerID, unsigned int uiPeerIDLen, void *pPeerPublicKey, void *pPeerTmpPublicKey, void *hAgreementHandle, void *pSelfPublicKey, void *pSelfTmpPublicKey, void **phKeyHandle) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("agreement-key")); append_token(o.key_ref, sizeof(o.key_ref), "isk_index", uiISKIndex); append_token(o.payload, sizeof(o.payload), "key_bits", uiKeyBits); append_ptr(o.payload, sizeof(o.payload), "peer_id", pucPeerID); append_token(o.payload, sizeof(o.payload), "peer_id_len", uiPeerIDLen); append_ptr(o.payload, sizeof(o.payload), "peer_pub", pPeerPublicKey); append_ptr(o.payload, sizeof(o.payload), "peer_tmp_pub", pPeerTmpPublicKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "agreement_handle", hAgreementHandle); append_ptr(o.aux_payload, sizeof(o.aux_payload), "self_pub", pSelfPublicKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "self_tmp_pub", pSelfTmpPublicKey); append_ptr(o.aux_payload, sizeof(o.aux_payload), "key_handle", phKeyHandle); return route_sym_encrypt(CCM_ALG_SM2, &o); }
int CCM_HashInit(void *hSessionHandle, unsigned int uiAlgID, void *pExParams) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("hash-init")); append_ptr(o.aux_payload, sizeof(o.aux_payload), "ex_params", pExParams); return route_hash(uiAlgID, &o); }
int CCM_HashUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("hash-update")); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); return route_hash(CCM_ALG_AUTO, &o); }
int CCM_HashFinal(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("hash-final")); append_ptr(o.aux_payload, sizeof(o.aux_payload), "hash", pucHash); append_ptr(o.aux_payload, sizeof(o.aux_payload), "hash_len", puiHashLen); return route_hash(CCM_ALG_AUTO, &o); }
int CCM_Mac(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *hKeyHandle, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucMac, unsigned int *puiMacLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("mac")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "key_handle", hKeyHandle); append_ptr(o.payload, sizeof(o.payload), "iv", pucIV); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "mac", pucMac); append_ptr(o.aux_payload, sizeof(o.aux_payload), "mac_len", puiMacLen); return route_mac(uiAlgID, &o); }
int CCM_HybridSign(void *hSessionHandle, unsigned int uiMainAlgID, unsigned int uiMainKeyIndex, CCM_HybridExParams *pHybridParams, unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucSignature, unsigned int *puiSigLen) { return CCM_Sign(hSessionHandle, uiMainAlgID, uiMainKeyIndex, NULL, 0U, pucData, uiDataLen, pucSignature, puiSigLen, pHybridParams); }
int CCM_HybridVerify(void *hSessionHandle, unsigned int uiMainAlgID, unsigned int uiMainKeyIndex, void *pMainExternalKey, CCM_HybridExParams *pHybridParams, unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucSignature, unsigned int uiSigLen) { return CCM_Verify(hSessionHandle, uiMainAlgID, uiMainKeyIndex, pMainExternalKey, 0U, pucData, uiDataLen, pucSignature, uiSigLen, pHybridParams); }
int CCM_HybridAgreement(void *hSessionHandle, unsigned int uiAlgID_ECC, unsigned int uiAlgID_PQC, unsigned int uiISKIndex, unsigned int uiKyberKeyIndex, void *pPeerECCPubKey, void *pPeerKyberPubKey, unsigned char *pucKyberCipher, void **phKeyHandle) {
    (void)hSessionHandle;
    ccm_json_options_t o;
    char json[2048];
    init_opts(&o, REQUEST_ID("hybrid-agreement"));
    append_token(o.key_ref, sizeof(o.key_ref), "isk_index", uiISKIndex);
    append_token(o.key_ref, sizeof(o.key_ref), "kyber_key_index", uiKyberKeyIndex);
    append_token(o.payload, sizeof(o.payload), "ecc_alg", uiAlgID_ECC);
    append_token(o.payload, sizeof(o.payload), "pqc_alg", uiAlgID_PQC);
    append_ptr(o.payload, sizeof(o.payload), "peer_ecc_pub", pPeerECCPubKey);
    append_ptr(o.payload, sizeof(o.payload), "peer_kyber_pub", pPeerKyberPubKey);
    append_ptr(o.aux_payload, sizeof(o.aux_payload), "kyber_cipher", pucKyberCipher);
    append_ptr(o.aux_payload, sizeof(o.aux_payload), "key_handle", phKeyHandle);
    return build_json("pqc", "kem_encap", uiAlgID_PQC, &o, json, sizeof(json));
}
int CCM_MessageEncode(unsigned int uiMessageType, void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pKeyOrCert, unsigned char *pucData, unsigned int uiDataLen, unsigned char *pucMessage, unsigned int *puiMessageLen, void *pExParams) { (void)hSessionHandle; (void)pExParams; ccm_json_options_t o; init_opts(&o, REQUEST_ID("msg-enc")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "key_or_cert", pKeyOrCert); append_token(o.payload, sizeof(o.payload), "message_type", uiMessageType); append_ptr(o.payload, sizeof(o.payload), "data", pucData); append_token(o.payload, sizeof(o.payload), "data_len", uiDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "message", pucMessage); append_ptr(o.aux_payload, sizeof(o.aux_payload), "message_len", puiMessageLen); if (uiMessageType == 1U || uiMessageType == 2U) return route_asym_encrypt(uiAlgID, &o); if (uiMessageType == 3U) return route_hash(uiAlgID, &o); return route_asym_encrypt(uiAlgID, &o); }
int CCM_MessageDecode(unsigned int uiMessageType, void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyIndex, void *pKeyOrCert, unsigned char *pucMessage, unsigned int uiMessageLen, unsigned char *pucData, unsigned int *puiDataLen, void *pExParams) { (void)hSessionHandle; (void)pExParams; ccm_json_options_t o; init_opts(&o, REQUEST_ID("msg-dec")); append_token(o.key_ref, sizeof(o.key_ref), "key_index", uiKeyIndex); append_ptr(o.key_ref, sizeof(o.key_ref), "key_or_cert", pKeyOrCert); append_token(o.payload, sizeof(o.payload), "message_type", uiMessageType); append_ptr(o.payload, sizeof(o.payload), "message", pucMessage); append_token(o.payload, sizeof(o.payload), "message_len", uiMessageLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "data", pucData); append_ptr(o.aux_payload, sizeof(o.aux_payload), "data_len", puiDataLen); if (uiMessageType == 1U || uiMessageType == 2U) return route_asym_decrypt(uiAlgID, &o); if (uiMessageType == 3U) return route_hash(uiAlgID, &o); return route_asym_decrypt(uiAlgID, &o); }
int CCM_MessageParseSignedData(void *hSessionHandle, unsigned char *pucSignedData, unsigned int uiSignedDataLen, unsigned char *pucInfo, unsigned int *puiInfoLen) { (void)hSessionHandle; ccm_json_options_t o; init_opts(&o, REQUEST_ID("msg-parse-signed")); append_ptr(o.payload, sizeof(o.payload), "signed_data", pucSignedData); append_token(o.payload, sizeof(o.payload), "signed_data_len", uiSignedDataLen); append_ptr(o.aux_payload, sizeof(o.aux_payload), "info", pucInfo); append_ptr(o.aux_payload, sizeof(o.aux_payload), "info_len", puiInfoLen); return route_asym_decrypt(CCM_ALG_AUTO, &o); }
