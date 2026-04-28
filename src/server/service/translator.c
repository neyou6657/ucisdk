#include "translator.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *backend_profile;
    device_type_t type;
    api_domain_t domain;
    api_action_t action;
    const char *algorithm;
    const char *backend_call;
} translation_rule_t;

static void append_text(char *dst, size_t dst_sz, const char *src) {
    size_t used = strlen(dst);
    size_t i = 0;
    if (used >= dst_sz) {
        return;
    }
    while (src[i] != '\0' && used + 1 < dst_sz) {
        dst[used++] = src[i++];
    }
    dst[used] = '\0';
}

static const translation_rule_t g_rules[] = {
    {"swsds-classic", DEV_CLASSIC, DOMAIN_DEVICE, ACTION_GET_DEVICE_INFO,           "auto",       "SDF_GetDeviceInfo"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_DEVICE, ACTION_GENERATE_RANDOM,           "auto",       "SDF_GenerateRandom"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_GET_PRIVATE_KEY_ACCESS,    "auto",       "SDF_GetPrivateKeyAccessRight"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_RELEASE_PRIVATE_KEY_ACCESS,"auto",       "SDF_ReleasePrivateKeyAccessRight"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_GENERATE_KEY_PAIR,         "rsa",        "SDF_GenerateKeyPair_RSA"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_GENERATE_KEY_PAIR,         "sm2",        "SDF_GenerateKeyPair_ECC"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_EXPORT_PUBLIC_KEY,         "rsa",        "SDF_ExportSignPublicKey_RSA"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_EXPORT_PUBLIC_KEY,         "sm2",        "SDF_ExportSignPublicKey_ECC"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_IMPORT_KEY,                "auto",       "SDF_ImportKey"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_KEY,    ACTION_DESTROY_KEY,               "auto",       "SDF_DestroyKey"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_ASYM,   ACTION_SIGN,                      "sm2",        "SDF_InternalSign_ECC_Ex"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_ASYM,   ACTION_VERIFY,                    "sm2",        "SDF_InternalVerify_ECC_Ex"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_ASYM,   ACTION_ENCRYPT,                   "sm2",        "SDF_InternalEncrypt_ECC"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_ASYM,   ACTION_DECRYPT,                   "sm2",        "SDF_InternalDecrypt_ECC"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_ASYM,   ACTION_SIGN,                      "rsa",        "SDF_InternalPrivateKeyOperation_RSA"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_ASYM,   ACTION_VERIFY,                    "rsa",        "SDF_InternalPublicKeyOperation_RSA"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_SYM,    ACTION_ENCRYPT,                   "sm4-cbc",    "SDF_Encrypt"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_SYM,    ACTION_DECRYPT,                   "sm4-cbc",    "SDF_Decrypt"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_SYM,    ACTION_MAC,                       "sm4-mac",    "SDF_CalculateMAC"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_HASH,   ACTION_HASH,                      "sm3",        "SDF_HashInit/SDF_HashUpdate/SDF_HashFinal"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_FILE,   ACTION_CREATE_FILE,               "auto",       "SDF_CreateFile"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_FILE,   ACTION_READ_FILE,                 "auto",       "SDF_ReadFile"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_FILE,   ACTION_WRITE_FILE,                "auto",       "SDF_WriteFile"},
    {"swsds-classic", DEV_CLASSIC, DOMAIN_FILE,   ACTION_DELETE_FILE,               "auto",       "SDF_DeleteFile"},

    {"gm3000-skf",    DEV_CLASSIC, DOMAIN_DEVICE, ACTION_GET_DEVICE_INFO,           "auto",       "SKF_GetDevInfo"},
    {"gm3000-skf",    DEV_CLASSIC, DOMAIN_DEVICE, ACTION_GENERATE_RANDOM,           "auto",       "SKF_GenRandom"},
    {"gm3000-skf",    DEV_CLASSIC, DOMAIN_HASH,   ACTION_HASH,                      "sm3",        "SKF_Digest"},

    {"swsds-pqc",     DEV_PQC,     DOMAIN_DEVICE, ACTION_GET_DEVICE_INFO,           "auto",       "SDF_GetDeviceInfo"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_DEVICE, ACTION_GENERATE_RANDOM,           "auto",       "SDF_GenerateRandom"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_KEY,    ACTION_GET_PRIVATE_KEY_ACCESS,    "auto",       "SDF_GetPrivateKeyAccessRight"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_KEY,    ACTION_RELEASE_PRIVATE_KEY_ACCESS,"auto",       "SDF_ReleasePrivateKeyAccessRight"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_KEY,    ACTION_GENERATE_KEY_PAIR,         "dilithium3", "SDF_GenerateKeyPair_Dilithium"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_KEY,    ACTION_GENERATE_KEY_PAIR,         "kyber768",   "SDF_GenerateKeyPairKyber"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_KEY,    ACTION_GENERATE_KEY_PAIR,         "mlkem768",   "SDF_GenerateKeyPairKyber"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_PQC,    ACTION_SIGN,                      "dilithium3", "SDF_Sign_Dilithium"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_PQC,    ACTION_VERIFY,                    "dilithium3", "SDF_Verify_Dilithium"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_PQC,    ACTION_KEM_ENCAP,                 "kyber768",   "SDF_Encap_Kyber"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_PQC,    ACTION_KEM_DECAP,                 "kyber768",   "SDF_Decap_Kyber"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_PQC,    ACTION_KEM_ENCAP,                 "mlkem768",   "SDF_Encap_Kyber"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_PQC,    ACTION_KEM_DECAP,                 "mlkem768",   "SDF_Decap_Kyber"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_HASH,   ACTION_HASH,                      "sm3",        "SDF_HashInit/SDF_HashUpdate/SDF_HashFinal"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_FILE,   ACTION_CREATE_FILE,               "auto",       "SDF_CreateFile"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_FILE,   ACTION_READ_FILE,                 "auto",       "SDF_ReadFile"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_FILE,   ACTION_WRITE_FILE,                "auto",       "SDF_WriteFile"},
    {"swsds-pqc",     DEV_PQC,     DOMAIN_FILE,   ACTION_DELETE_FILE,               "auto",       "SDF_DeleteFile"}
};

static int find_rule(const device_resource_t *device,
                     api_domain_t domain,
                     api_action_t action,
                     const char *algorithm,
                     const translation_rule_t **out_rule) {
    size_t i;
    for (i = 0; i < sizeof(g_rules) / sizeof(g_rules[0]); ++i) {
        const translation_rule_t *rule = &g_rules[i];
        if (rule->type != device->type) {
            continue;
        }
        if (strcmp(rule->backend_profile, device->backend_profile) != 0) {
            continue;
        }
        if (rule->domain != domain || rule->action != action) {
            continue;
        }
        if (strcmp(rule->algorithm, algorithm) == 0 || strcmp(rule->algorithm, "auto") == 0) {
            *out_rule = rule;
            return 0;
        }
    }
    return -1;
}

int translate_backend_call(api_domain_t domain,
                           api_action_t action,
                           const char *algorithm,
                           const char *payload,
                           const char *aux_payload,
                           const char *key_ref,
                           const device_resource_t *device,
                           translated_call_t *out,
                           char *errbuf,
                           size_t errbuf_sz) {
    const translation_rule_t *rule = NULL;
    memset(out, 0, sizeof(*out));
    out->call.domain = domain;
    out->call.action = action;
    snprintf(out->call.algorithm, sizeof(out->call.algorithm), "%s", algorithm);
    snprintf(out->call.key_ref, sizeof(out->call.key_ref), "%s", key_ref == NULL ? "" : key_ref);
    snprintf(out->call.payload, sizeof(out->call.payload), "%s", payload == NULL ? "" : payload);
    snprintf(out->call.aux_payload, sizeof(out->call.aux_payload), "%s", aux_payload == NULL ? "" : aux_payload);
    out->backend_name[0] = '\0';
    append_text(out->backend_name, sizeof(out->backend_name), device_type_to_string(device->type));
    append_text(out->backend_name, sizeof(out->backend_name), ":");
    append_text(out->backend_name, sizeof(out->backend_name), device->backend_profile);

    if (find_rule(device, domain, action, algorithm, &rule) != 0) {
        snprintf(errbuf, errbuf_sz,
                 "no translation rule for profile=%s domain=%s action=%s alg=%s",
                 device->backend_profile,
                 domain_to_string(domain),
                 action_to_string(action),
                 algorithm);
        return -1;
    }

    snprintf(out->backend_call_name, sizeof(out->backend_call_name), "%s", rule->backend_call);
    return 0;
}

int translate_request_for_device(const request_t *req,
                                 const device_resource_t *device,
                                 translated_call_t *out,
                                 char *errbuf,
                                 size_t errbuf_sz) {
    return translate_backend_call(req->domain,
                                  req->action,
                                  req->algorithm,
                                  req->payload,
                                  req->aux_payload,
                                  req->key_ref,
                                  device,
                                  out,
                                  errbuf,
                                  errbuf_sz);
}
