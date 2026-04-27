#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include "swskfapi.h"

typedef enum {
    UAPI_OK = 0,
    UAPI_ERR = -1,
    UAPI_UNSUPPORTED = -2,
    UAPI_INVALID_ARG = -3,
    UAPI_BUFFER_TOO_SMALL = -4,
    UAPI_AUTH_FAILED = -5
} uapi_status_t;

typedef enum {
    UOP_NONE = 0,
    UOP_DEVICE,
    UOP_KEY,
    UOP_ASYM,
    UOP_SYM,
    UOP_HASH,
    UOP_FILE,
    UOP_PQC,
    UOP_AUTH
} uapi_domain_t;

typedef enum {
    UACT_NONE = 0,
    UACT_GET_INFO,
    UACT_GEN_RANDOM,
    UACT_VERIFY_PIN,
    UACT_SIGN,
    UACT_VERIFY,
    UACT_ENCRYPT,
    UACT_DECRYPT,
    UACT_DIGEST,
    UACT_READ_FILE,
    UACT_WRITE_FILE,
    UACT_KEM_ENCAP,
    UACT_KEM_DECAP
} uapi_action_t;

typedef struct {
    uapi_action_t action;
    const char *device_name;
    const char *app_name;
    const char *container_name;
    const char *pin;
    ULONG pin_type;
    const char *file_name;
    ULONG offset;
    ULONG rights_read;
    ULONG rights_write;

    const unsigned char *input;
    ULONG input_len;
    const unsigned char *aux_input;
    ULONG aux_input_len;
    unsigned char *output;
    ULONG *output_len;

    const char *algorithm;
    ULONG alg_id;
    ULONG key_bits;
    ULONG key_index;
    ULONG security_level;
    ULONG randomize_signing;

    HAPPLICATION h_app;
    HCONTAINER h_container;
    HANDLE h_key;
    DEVHANDLE h_dev;
} uapi_request_t;

typedef struct {
    int status;
    ULONG vendor_rv;
    ULONG retry_count;
    char message[256];
} uapi_response_t;

typedef struct {
    DEVHANDLE dev;
    HAPPLICATION app;
    HCONTAINER container;
    HANDLE key;
    int owns_dev;
    int owns_app;
    int owns_container;
    int owns_key;
} skf_session_t;

typedef struct skf_adapter skf_adapter_t;

typedef struct {
    int (*device_manage)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*key_manage)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*asym_crypto)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*sym_crypto)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*hash_ops)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*file_ops)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*pqc_ops)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
    int (*auth_ops)(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess);
} skf_adapter_ops_t;

struct skf_adapter {
    void *lib;
    skf_adapter_ops_t ops;

    ULONG (*SKF_ConnectDev)(LPSTR, DEVHANDLE *);
    ULONG (*SKF_DisConnectDev)(DEVHANDLE);
    ULONG (*SKF_OpenApplication)(DEVHANDLE, LPSTR, HAPPLICATION *);
    ULONG (*SKF_CloseApplication)(HAPPLICATION);
    ULONG (*SKF_OpenContainer)(HAPPLICATION, LPSTR, HCONTAINER *);
    ULONG (*SKF_CloseContainer)(HCONTAINER);
    ULONG (*SKF_GetDevInfo)(DEVHANDLE, DEVINFO *);
    ULONG (*SKF_GenRandom)(DEVHANDLE, BYTE *, ULONG);
    ULONG (*SKF_VerifyPIN)(HAPPLICATION, ULONG, LPSTR, ULONG *);

    ULONG (*SKF_RSASignData)(HCONTAINER, BYTE *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_RSAVerify)(DEVHANDLE, RSAPUBLICKEYBLOB *, BYTE *, ULONG, BYTE *, ULONG);
    ULONG (*SKF_ECCSignData)(HCONTAINER, BYTE *, ULONG, PECCSIGNATUREBLOB);
    ULONG (*SKF_ECCVerify)(DEVHANDLE, ECCPUBLICKEYBLOB *, BYTE *, ULONG, PECCSIGNATUREBLOB);
    ULONG (*SKF_ECCDecrypt)(HCONTAINER, ULONG, PECCCIPHERBLOB, BYTE *, ULONG *);
    ULONG (*SKF_RSADecrypt)(HCONTAINER, ULONG, BYTE *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_ExtECCEncrypt)(DEVHANDLE, ECCPUBLICKEYBLOB *, BYTE *, ULONG, PECCCIPHERBLOB);
    ULONG (*SKF_ExtECCDecrypt)(DEVHANDLE, ECCPRIVATEKEYBLOB *, PECCCIPHERBLOB, BYTE *, ULONG *);
    ULONG (*SKF_ExtRSAPubKeyOperation)(DEVHANDLE, RSAPUBLICKEYBLOB *, BYTE *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_ExtRSAPriKeyOperation)(DEVHANDLE, RSAPRIVATEKEYBLOB *, BYTE *, ULONG, BYTE *, ULONG *);

    ULONG (*SKF_SetSymmKey)(DEVHANDLE, BYTE *, ULONG, HANDLE *);
    ULONG (*SKF_EncryptInit)(HANDLE, BLOCKCIPHERPARAM);
    ULONG (*SKF_Encrypt)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_DecryptInit)(HANDLE, BLOCKCIPHERPARAM);
    ULONG (*SKF_Decrypt)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_CloseHandle)(HANDLE);

    ULONG (*SKF_DigestInit)(DEVHANDLE, ULONG, ECCPUBLICKEYBLOB *, unsigned char *, ULONG, HANDLE *);
    ULONG (*SKF_Digest)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_DigestUpdate)(HANDLE, BYTE *, ULONG);
    ULONG (*SKF_DigestFinal)(HANDLE, BYTE *, ULONG *);

    ULONG (*SKF_ReadFile)(HAPPLICATION, LPSTR, ULONG, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_WriteFile)(HAPPLICATION, LPSTR, ULONG, BYTE *, ULONG);

    ULONG (*SKF_GenerateKeyPairKyber)(DEVHANDLE, ULONG, ULONG, KyberPublicKey *, KyberPrivateKey *);
    ULONG (*SKF_Encap_Kyber)(DEVHANDLE, ULONG, KyberPublicKey *, ULONG, BYTE *, ULONG *, BYTE *, ULONG *);
    ULONG (*SKF_Decap_Kyber)(DEVHANDLE, BYTE *, ULONG, ULONG, KyberPrivateKey *, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_GenerateKeyPair_Dilithium)(DEVHANDLE, ULONG, ULONG, DilithiumPublicKey *, DilithiumPrivateKey *);
    ULONG (*SKF_Sign_Dilithium)(DEVHANDLE, BYTE *, ULONG, ULONG, DilithiumPrivateKey *, BYTE *, ULONG, ULONG, ULONG, ULONG, ULONG, BYTE *, ULONG *);
    ULONG (*SKF_Verify_Dilithium)(DEVHANDLE, ULONG, DilithiumPublicKey *, BYTE *, ULONG, ULONG, ULONG, ULONG, BYTE *, ULONG, BYTE *, ULONG);
};

#define SKF_LOAD(ad, fn) do { \
    (ad)->fn = dlsym((ad)->lib, #fn); \
    if (!(ad)->fn) return UAPI_ERR; \
} while (0)

static void set_resp(uapi_response_t *resp, int status, ULONG rv, const char *msg) {
    if (!resp) return;
    resp->status = status;
    resp->vendor_rv = rv;
    resp->retry_count = 0;
    if (msg) {
        snprintf(resp->message, sizeof(resp->message), "%s", msg);
    } else {
        resp->message[0] = '\0';
    }
}

static ULONG alg_to_skf_id(const char *algorithm) {
    if (!algorithm) return 0;
    if (strcmp(algorithm, "sm2") == 0) return SGD_SM2_1;
    if (strcmp(algorithm, "sm2-sign") == 0) return SGD_SM2_1;
    if (strcmp(algorithm, "sm2-enc") == 0) return SGD_SM2_3;
    if (strcmp(algorithm, "rsa") == 0) return SGD_RSA;
    if (strcmp(algorithm, "rsa-sign") == 0) return SGD_RSA_SIGN;
    if (strcmp(algorithm, "rsa-enc") == 0) return SGD_RSA_ENC;
    if (strcmp(algorithm, "sm4") == 0) return SGD_SMS4_ECB;
    if (strcmp(algorithm, "sm4-ecb") == 0) return SGD_SMS4_ECB;
    if (strcmp(algorithm, "sm4-cbc") == 0) return SGD_SMS4_CBC;
    if (strcmp(algorithm, "sm3") == 0) return SGD_SM3;
    if (strcmp(algorithm, "sha256") == 0) return SGD_SHA256;
    return 0;
}

static int session_open(skf_adapter_t *ad, const uapi_request_t *req, skf_session_t *sess, uapi_response_t *resp) {
    ULONG rv;
    if (!ad || !req || !sess) return UAPI_INVALID_ARG;
    memset(sess, 0, sizeof(*sess));

    if (req->h_dev) {
        sess->dev = req->h_dev;
    } else if (req->device_name) {
        rv = ad->SKF_ConnectDev((LPSTR)req->device_name, &sess->dev);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_ConnectDev failed");
            return UAPI_ERR;
        }
        sess->owns_dev = 1;
    }

    if (req->h_app) {
        sess->app = req->h_app;
    } else if (sess->dev && req->app_name) {
        rv = ad->SKF_OpenApplication(sess->dev, (LPSTR)req->app_name, &sess->app);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_OpenApplication failed");
            return UAPI_ERR;
        }
        sess->owns_app = 1;
    }

    if (req->h_container) {
        sess->container = req->h_container;
    } else if (sess->app && req->container_name) {
        rv = ad->SKF_OpenContainer(sess->app, (LPSTR)req->container_name, &sess->container);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_OpenContainer failed");
            return UAPI_ERR;
        }
        sess->owns_container = 1;
    }

    if (req->h_key) {
        sess->key = req->h_key;
    }

    return UAPI_OK;
}

static void session_close(skf_adapter_t *ad, skf_session_t *sess) {
    if (!ad || !sess) return;
    if (sess->owns_key && sess->key && ad->SKF_CloseHandle) {
        ad->SKF_CloseHandle(sess->key);
    }
    if (sess->owns_container && sess->container && ad->SKF_CloseContainer) {
        ad->SKF_CloseContainer(sess->container);
    }
    if (sess->owns_app && sess->app && ad->SKF_CloseApplication) {
        ad->SKF_CloseApplication(sess->app);
    }
    if (sess->owns_dev && sess->dev && ad->SKF_DisConnectDev) {
        ad->SKF_DisConnectDev(sess->dev);
    }
    memset(sess, 0, sizeof(*sess));
}

static int skf_device_manage(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;
    if (req->action == UACT_GET_INFO) {
        DEVINFO info;
        ULONG rv;
        if (!sess->dev) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "device handle required");
            return UAPI_INVALID_ARG;
        }
        if (!req->output || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "output buffer required");
            return UAPI_INVALID_ARG;
        }
        if (*req->output_len < (ULONG)sizeof(info)) {
            *req->output_len = (ULONG)sizeof(info);
            set_resp(resp, UAPI_BUFFER_TOO_SMALL, 0, "buffer too small");
            return UAPI_BUFFER_TOO_SMALL;
        }
        memset(&info, 0, sizeof(info));
        rv = ad->SKF_GetDevInfo(sess->dev, &info);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_GetDevInfo failed");
            return UAPI_ERR;
        }
        memcpy(req->output, &info, sizeof(info));
        *req->output_len = (ULONG)sizeof(info);
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }
    if (req->action == UACT_GEN_RANDOM) {
        ULONG rv;
        if (!sess->dev || !req->output || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "device/output required");
            return UAPI_INVALID_ARG;
        }
        rv = ad->SKF_GenRandom(sess->dev, req->output, *req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_GenRandom failed");
            return UAPI_ERR;
        }
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }
    set_resp(resp, UAPI_UNSUPPORTED, 0, "unsupported device action");
    return UAPI_UNSUPPORTED;
}

static int skf_key_manage(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    (void)ad; (void)req; (void)resp; (void)sess;
    set_resp(resp, UAPI_UNSUPPORTED, 0, "key manage not implemented in this adapter.c");
    return UAPI_UNSUPPORTED;
}

static int skf_asym_crypto(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    ULONG rv;
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;

    if (req->action == UACT_SIGN) {
        if (!req->algorithm || !req->input || !req->output || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "sign args invalid");
            return UAPI_INVALID_ARG;
        }
        if (strcmp(req->algorithm, "rsa") == 0 || strcmp(req->algorithm, "rsa-sign") == 0) {
            rv = ad->SKF_RSASignData(sess->container, (BYTE *)req->input, req->input_len, req->output, req->output_len);
            if (rv != SAR_OK) {
                set_resp(resp, UAPI_ERR, rv, "SKF_RSASignData failed");
                return UAPI_ERR;
            }
            set_resp(resp, UAPI_OK, rv, "ok");
            return UAPI_OK;
        }
        if (strcmp(req->algorithm, "sm2") == 0 || strcmp(req->algorithm, "sm2-sign") == 0) {
            ECCSIGNATUREBLOB sig;
            if (*req->output_len < (ULONG)sizeof(sig)) {
                *req->output_len = (ULONG)sizeof(sig);
                set_resp(resp, UAPI_BUFFER_TOO_SMALL, 0, "buffer too small");
                return UAPI_BUFFER_TOO_SMALL;
            }
            memset(&sig, 0, sizeof(sig));
            rv = ad->SKF_ECCSignData(sess->container, (BYTE *)req->input, req->input_len, &sig);
            if (rv != SAR_OK) {
                set_resp(resp, UAPI_ERR, rv, "SKF_ECCSignData failed");
                return UAPI_ERR;
            }
            memcpy(req->output, &sig, sizeof(sig));
            *req->output_len = (ULONG)sizeof(sig);
            set_resp(resp, UAPI_OK, rv, "ok");
            return UAPI_OK;
        }
    }

    if (req->action == UACT_VERIFY) {
        if (!req->algorithm || !req->input || !req->aux_input) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "verify args invalid");
            return UAPI_INVALID_ARG;
        }
        if (strcmp(req->algorithm, "rsa") == 0 || strcmp(req->algorithm, "rsa-sign") == 0) {
            if (req->output_len) *req->output_len = 0;
            set_resp(resp, UAPI_UNSUPPORTED, 0, "RSA verify requires public key blob in adapter request extension");
            return UAPI_UNSUPPORTED;
        }
        if (strcmp(req->algorithm, "sm2") == 0 || strcmp(req->algorithm, "sm2-sign") == 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "SM2 verify requires public key blob in adapter request extension");
            return UAPI_UNSUPPORTED;
        }
    }

    if (req->action == UACT_ENCRYPT) {
        if (strcmp(req->algorithm, "rsa") == 0 || strcmp(req->algorithm, "rsa-enc") == 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "RSA public encrypt requires public key blob extension");
            return UAPI_UNSUPPORTED;
        }
        if (strcmp(req->algorithm, "sm2") == 0 || strcmp(req->algorithm, "sm2-enc") == 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "SM2 encrypt requires public key blob extension");
            return UAPI_UNSUPPORTED;
        }
    }

    if (req->action == UACT_DECRYPT) {
        if (strcmp(req->algorithm, "rsa") == 0 || strcmp(req->algorithm, "rsa-enc") == 0) {
            rv = ad->SKF_RSADecrypt(sess->container, KEY_TYPE_KEYEXCHANGE, (BYTE *)req->input, req->input_len, req->output, req->output_len);
            if (rv != SAR_OK) {
                set_resp(resp, UAPI_ERR, rv, "SKF_RSADecrypt failed");
                return UAPI_ERR;
            }
            set_resp(resp, UAPI_OK, rv, "ok");
            return UAPI_OK;
        }
        if (strcmp(req->algorithm, "sm2") == 0 || strcmp(req->algorithm, "sm2-enc") == 0) {
            rv = ad->SKF_ECCDecrypt(sess->container, KEY_TYPE_KEYEXCHANGE, (PECCCIPHERBLOB)req->input, req->output, req->output_len);
            if (rv != SAR_OK) {
                set_resp(resp, UAPI_ERR, rv, "SKF_ECCDecrypt failed");
                return UAPI_ERR;
            }
            set_resp(resp, UAPI_OK, rv, "ok");
            return UAPI_OK;
        }
    }

    set_resp(resp, UAPI_UNSUPPORTED, 0, "unsupported asym action");
    return UAPI_UNSUPPORTED;
}

static int skf_sym_crypto(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    ULONG rv;
    BLOCKCIPHERPARAM param;
    ULONG alg_id;
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;
    if (!sess->dev || !req->aux_input || req->aux_input_len == 0) {
        set_resp(resp, UAPI_INVALID_ARG, 0, "sym key bytes required in aux_input");
        return UAPI_INVALID_ARG;
    }
    memset(&param, 0, sizeof(param));
    alg_id = req->alg_id ? req->alg_id : alg_to_skf_id(req->algorithm);
    if (alg_id == 0) {
        set_resp(resp, UAPI_INVALID_ARG, 0, "unknown sym algorithm");
        return UAPI_INVALID_ARG;
    }

    rv = ad->SKF_SetSymmKey(sess->dev, (BYTE *)req->aux_input, alg_id, &sess->key);
    if (rv != SAR_OK) {
        set_resp(resp, UAPI_ERR, rv, "SKF_SetSymmKey failed");
        return UAPI_ERR;
    }
    sess->owns_key = 1;

    if (req->action == UACT_ENCRYPT) {
        rv = ad->SKF_EncryptInit(sess->key, param);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_EncryptInit failed");
            return UAPI_ERR;
        }
        rv = ad->SKF_Encrypt(sess->key, (BYTE *)req->input, req->input_len, req->output, req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_Encrypt failed");
            return UAPI_ERR;
        }
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }
    if (req->action == UACT_DECRYPT) {
        rv = ad->SKF_DecryptInit(sess->key, param);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_DecryptInit failed");
            return UAPI_ERR;
        }
        rv = ad->SKF_Decrypt(sess->key, (BYTE *)req->input, req->input_len, req->output, req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_Decrypt failed");
            return UAPI_ERR;
        }
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }
    set_resp(resp, UAPI_UNSUPPORTED, 0, "unsupported sym action");
    return UAPI_UNSUPPORTED;
}

static int skf_hash_ops(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    ULONG rv;
    HANDLE hhash = NULL;
    ULONG alg_id;
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;
    if (req->action != UACT_DIGEST) {
        set_resp(resp, UAPI_UNSUPPORTED, 0, "unsupported hash action");
        return UAPI_UNSUPPORTED;
    }
    alg_id = req->alg_id ? req->alg_id : alg_to_skf_id(req->algorithm);
    if (!sess->dev || alg_id == 0 || !req->output || !req->output_len) {
        set_resp(resp, UAPI_INVALID_ARG, 0, "invalid hash args");
        return UAPI_INVALID_ARG;
    }
    rv = ad->SKF_DigestInit(sess->dev, alg_id, NULL, NULL, 0, &hhash);
    if (rv != SAR_OK) {
        set_resp(resp, UAPI_ERR, rv, "SKF_DigestInit failed");
        return UAPI_ERR;
    }
    rv = ad->SKF_Digest(hhash, (BYTE *)req->input, req->input_len, req->output, req->output_len);
    if (ad->SKF_CloseHandle) ad->SKF_CloseHandle(hhash);
    if (rv != SAR_OK) {
        set_resp(resp, UAPI_ERR, rv, "SKF_Digest failed");
        return UAPI_ERR;
    }
    set_resp(resp, UAPI_OK, rv, "ok");
    return UAPI_OK;
}

static int skf_file_ops(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    ULONG rv;
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;
    if (!sess->app || !req->file_name) {
        set_resp(resp, UAPI_INVALID_ARG, 0, "application/file_name required");
        return UAPI_INVALID_ARG;
    }
    if (req->action == UACT_READ_FILE) {
        rv = ad->SKF_ReadFile(sess->app, (LPSTR)req->file_name, req->offset, req->input_len, req->output, req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_ReadFile failed");
            return UAPI_ERR;
        }
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }
    if (req->action == UACT_WRITE_FILE) {
        rv = ad->SKF_WriteFile(sess->app, (LPSTR)req->file_name, req->offset, (BYTE *)req->input, req->input_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_WriteFile failed");
            return UAPI_ERR;
        }
        if (req->output_len) *req->output_len = 0;
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }
    set_resp(resp, UAPI_UNSUPPORTED, 0, "unsupported file action");
    return UAPI_UNSUPPORTED;
}

static int skf_pqc_ops(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    ULONG rv;
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;
    if (!sess->dev) {
        set_resp(resp, UAPI_INVALID_ARG, 0, "device required");
        return UAPI_INVALID_ARG;
    }

    if (req->action == UACT_KEM_ENCAP) {
        if (!req->algorithm || strcmp(req->algorithm, "kyber") != 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "only kyber kem in this adapter.c");
            return UAPI_UNSUPPORTED;
        }
        if (!req->aux_input || req->aux_input_len < sizeof(KyberPublicKey) || !req->output || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "kyber pubkey/output required");
            return UAPI_INVALID_ARG;
        }
        {
            ULONG ct_len = *req->output_len;
            ULONG key_len = 64;
            unsigned char keybuf[64];
            rv = ad->SKF_Encap_Kyber(sess->dev, req->key_index, (KyberPublicKey *)req->aux_input,
                                     req->security_level, req->output, &ct_len, keybuf, &key_len);
            if (rv != SAR_OK) {
                set_resp(resp, UAPI_ERR, rv, "SKF_Encap_Kyber failed");
                return UAPI_ERR;
            }
            *req->output_len = ct_len;
            set_resp(resp, UAPI_OK, rv, "ok");
            return UAPI_OK;
        }
    }

    if (req->action == UACT_KEM_DECAP) {
        if (!req->algorithm || strcmp(req->algorithm, "kyber") != 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "only kyber kem in this adapter.c");
            return UAPI_UNSUPPORTED;
        }
        if (!req->aux_input || req->aux_input_len < sizeof(KyberPrivateKey) || !req->output || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "kyber prikey/output required");
            return UAPI_INVALID_ARG;
        }
        rv = ad->SKF_Decap_Kyber(sess->dev, (BYTE *)req->input, req->input_len, req->key_index,
                                 (KyberPrivateKey *)req->aux_input, req->security_level,
                                 req->output, req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_Decap_Kyber failed");
            return UAPI_ERR;
        }
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }

    if (req->action == UACT_SIGN) {
        if (!req->algorithm || strcmp(req->algorithm, "dilithium") != 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "only dilithium sign in this adapter.c");
            return UAPI_UNSUPPORTED;
        }
        if (!req->aux_input || req->aux_input_len < sizeof(DilithiumPrivateKey) || !req->output || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "dilithium prikey/output required");
            return UAPI_INVALID_ARG;
        }
        rv = ad->SKF_Sign_Dilithium(sess->dev, (BYTE *)req->input, req->input_len, req->key_index,
                                    (DilithiumPrivateKey *)req->aux_input, NULL, 0, SGD_SM3,
                                    32, req->security_level, req->randomize_signing,
                                    req->output, req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_Sign_Dilithium failed");
            return UAPI_ERR;
        }
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }

    if (req->action == UACT_VERIFY) {
        if (!req->algorithm || strcmp(req->algorithm, "dilithium") != 0) {
            set_resp(resp, UAPI_UNSUPPORTED, 0, "only dilithium verify in this adapter.c");
            return UAPI_UNSUPPORTED;
        }
        if (!req->aux_input || req->aux_input_len < sizeof(DilithiumPublicKey) || !req->output_len) {
            set_resp(resp, UAPI_INVALID_ARG, 0, "dilithium pubkey required");
            return UAPI_INVALID_ARG;
        }
        rv = ad->SKF_Verify_Dilithium(sess->dev, req->key_index, (DilithiumPublicKey *)req->aux_input,
                                      NULL, 0, SGD_SM3, 32, req->security_level,
                                      (BYTE *)req->input, req->input_len, req->output, *req->output_len);
        if (rv != SAR_OK) {
            set_resp(resp, UAPI_ERR, rv, "SKF_Verify_Dilithium failed");
            return UAPI_ERR;
        }
        *req->output_len = 0;
        set_resp(resp, UAPI_OK, rv, "ok");
        return UAPI_OK;
    }

    set_resp(resp, UAPI_UNSUPPORTED, 0, "unsupported pqc action");
    return UAPI_UNSUPPORTED;
}

static int skf_auth_ops(skf_adapter_t *ad, const uapi_request_t *req, uapi_response_t *resp, skf_session_t *sess) {
    ULONG rv, retry = 0;
    if (!ad || !req || !resp || !sess) return UAPI_INVALID_ARG;
    if (req->action != UACT_VERIFY_PIN || !sess->app || !req->pin) {
        set_resp(resp, UAPI_INVALID_ARG, 0, "application and pin required");
        return UAPI_INVALID_ARG;
    }
    rv = ad->SKF_VerifyPIN(sess->app, req->pin_type ? req->pin_type : USER_TYPE, (LPSTR)req->pin, &retry);
    resp->retry_count = retry;
    if (rv != SAR_OK) {
        set_resp(resp, UAPI_AUTH_FAILED, rv, "SKF_VerifyPIN failed");
        resp->retry_count = retry;
        return UAPI_AUTH_FAILED;
    }
    set_resp(resp, UAPI_OK, rv, "ok");
    resp->retry_count = retry;
    return UAPI_OK;
}

int skf_adapter_init(skf_adapter_t *ad, const char *so_path) {
    if (!ad || !so_path) return UAPI_INVALID_ARG;
    memset(ad, 0, sizeof(*ad));
    ad->lib = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
    if (!ad->lib) return UAPI_ERR;

    SKF_LOAD(ad, SKF_ConnectDev);
    SKF_LOAD(ad, SKF_DisConnectDev);
    SKF_LOAD(ad, SKF_OpenApplication);
    SKF_LOAD(ad, SKF_CloseApplication);
    SKF_LOAD(ad, SKF_OpenContainer);
    SKF_LOAD(ad, SKF_CloseContainer);
    SKF_LOAD(ad, SKF_GetDevInfo);
    SKF_LOAD(ad, SKF_GenRandom);
    SKF_LOAD(ad, SKF_VerifyPIN);

    SKF_LOAD(ad, SKF_RSASignData);
    SKF_LOAD(ad, SKF_RSAVerify);
    SKF_LOAD(ad, SKF_ECCSignData);
    SKF_LOAD(ad, SKF_ECCVerify);
    SKF_LOAD(ad, SKF_ECCDecrypt);
    SKF_LOAD(ad, SKF_RSADecrypt);
    SKF_LOAD(ad, SKF_ExtECCEncrypt);
    SKF_LOAD(ad, SKF_ExtECCDecrypt);
    SKF_LOAD(ad, SKF_ExtRSAPubKeyOperation);
    SKF_LOAD(ad, SKF_ExtRSAPriKeyOperation);

    SKF_LOAD(ad, SKF_SetSymmKey);
    SKF_LOAD(ad, SKF_EncryptInit);
    SKF_LOAD(ad, SKF_Encrypt);
    SKF_LOAD(ad, SKF_DecryptInit);
    SKF_LOAD(ad, SKF_Decrypt);
    SKF_LOAD(ad, SKF_CloseHandle);

    SKF_LOAD(ad, SKF_DigestInit);
    SKF_LOAD(ad, SKF_Digest);
    SKF_LOAD(ad, SKF_DigestUpdate);
    SKF_LOAD(ad, SKF_DigestFinal);

    SKF_LOAD(ad, SKF_ReadFile);
    SKF_LOAD(ad, SKF_WriteFile);

    SKF_LOAD(ad, SKF_GenerateKeyPairKyber);
    SKF_LOAD(ad, SKF_Encap_Kyber);
    SKF_LOAD(ad, SKF_Decap_Kyber);
    SKF_LOAD(ad, SKF_GenerateKeyPair_Dilithium);
    SKF_LOAD(ad, SKF_Sign_Dilithium);
    SKF_LOAD(ad, SKF_Verify_Dilithium);

    ad->ops.device_manage = skf_device_manage;
    ad->ops.key_manage = skf_key_manage;
    ad->ops.asym_crypto = skf_asym_crypto;
    ad->ops.sym_crypto = skf_sym_crypto;
    ad->ops.hash_ops = skf_hash_ops;
    ad->ops.file_ops = skf_file_ops;
    ad->ops.pqc_ops = skf_pqc_ops;
    ad->ops.auth_ops = skf_auth_ops;
    return UAPI_OK;
}

void skf_adapter_fini(skf_adapter_t *ad) {
    if (!ad) return;
    if (ad->lib) dlclose(ad->lib);
    memset(ad, 0, sizeof(*ad));
}

int skf_adapter_execute(skf_adapter_t *ad, uapi_domain_t domain, const uapi_request_t *req, uapi_response_t *resp) {
    skf_session_t sess;
    int rc;
    if (!ad || !req || !resp) return UAPI_INVALID_ARG;
    rc = session_open(ad, req, &sess, resp);
    if (rc != UAPI_OK) return rc;

    switch (domain) {
        case UOP_DEVICE: rc = ad->ops.device_manage(ad, req, resp, &sess); break;
        case UOP_KEY:    rc = ad->ops.key_manage(ad, req, resp, &sess); break;
        case UOP_ASYM:   rc = ad->ops.asym_crypto(ad, req, resp, &sess); break;
        case UOP_SYM:    rc = ad->ops.sym_crypto(ad, req, resp, &sess); break;
        case UOP_HASH:   rc = ad->ops.hash_ops(ad, req, resp, &sess); break;
        case UOP_FILE:   rc = ad->ops.file_ops(ad, req, resp, &sess); break;
        case UOP_PQC:    rc = ad->ops.pqc_ops(ad, req, resp, &sess); break;
        case UOP_AUTH:   rc = ad->ops.auth_ops(ad, req, resp, &sess); break;
        default:
            set_resp(resp, UAPI_UNSUPPORTED, 0, "unknown domain");
            rc = UAPI_UNSUPPORTED;
            break;
    }

    session_close(ad, &sess);
    return rc;
}

#ifdef SKF_ADAPTER_MAIN
int main(int argc, char **argv) {
    skf_adapter_t ad;
    uapi_request_t req;
    uapi_response_t resp;
    unsigned char out[256];
    ULONG out_len = sizeof(out);
    int rc;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <lib.so> <device_name> <app_name> <user_pin>\n", argv[0]);
        return 2;
    }

    rc = skf_adapter_init(&ad, argv[1]);
    if (rc != UAPI_OK) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.device_name = argv[2];
    req.app_name = argv[3];
    req.pin = argv[4];
    req.pin_type = USER_TYPE;
    req.action = UACT_VERIFY_PIN;

    rc = skf_adapter_execute(&ad, UOP_AUTH, &req, &resp);
    printf("verify_pin rc=%d rv=0x%08X retry=%u msg=%s\n", rc, resp.vendor_rv, resp.retry_count, resp.message);

    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.device_name = argv[2];
    req.action = UACT_GEN_RANDOM;
    req.output = out;
    req.output_len = &out_len;

    rc = skf_adapter_execute(&ad, UOP_DEVICE, &req, &resp);
    printf("gen_random rc=%d rv=0x%08X len=%u msg=%s\n", rc, resp.vendor_rv, out_len, resp.message);

    skf_adapter_fini(&ad);
    return 0;
}
#endif
