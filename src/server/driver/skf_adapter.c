#include "driver.h"
#include "protocol.h"
#include "skfapi.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GM3000_DEFAULT_LIB "./vendor/libgm3000.1.0.so"
#define GM3000_MAX_IO 2048U
#define GM3000_MAX_NAME 256U
#define GM3000_RESULT_HEX 512U
#define GM3000_DEFAULT_RIGHTS 0xFFFFFFFFU

typedef ULONG (*PFN_SKF_EnumDev)(BOOL, LPSTR, ULONG *);
typedef ULONG (*PFN_SKF_ConnectDev)(LPSTR, DEVHANDLE *);
typedef ULONG (*PFN_SKF_DisConnectDev)(DEVHANDLE);
typedef ULONG (*PFN_SKF_GetDevInfo)(DEVHANDLE, DEVINFO *);
typedef ULONG (*PFN_SKF_GenRandom)(DEVHANDLE, BYTE *, ULONG);
typedef ULONG (*PFN_SKF_OpenApplication)(DEVHANDLE, LPSTR, HAPPLICATION *);
typedef ULONG (*PFN_SKF_CloseApplication)(HAPPLICATION);
typedef ULONG (*PFN_SKF_VerifyPIN)(HAPPLICATION, ULONG, LPSTR, ULONG *);
typedef ULONG (*PFN_SKF_CreateContainer)(HAPPLICATION, LPSTR, HCONTAINER *);
typedef ULONG (*PFN_SKF_DeleteContainer)(HAPPLICATION, LPSTR);
typedef ULONG (*PFN_SKF_OpenContainer)(HAPPLICATION, LPSTR, HCONTAINER *);
typedef ULONG (*PFN_SKF_CloseContainer)(HCONTAINER);
typedef ULONG (*PFN_SKF_GenECCKeyPair)(HCONTAINER, ULONG, ECCPUBLICKEYBLOB *);
typedef ULONG (*PFN_SKF_GenRSAKeyPair)(HCONTAINER, ULONG, RSAPUBLICKEYBLOB *);
typedef ULONG (*PFN_SKF_ExportPublicKey)(HCONTAINER, BOOL, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_ECCSignData)(HCONTAINER, BYTE *, ULONG, ECCSIGNATUREBLOB *);
typedef ULONG (*PFN_SKF_ECCVerify)(DEVHANDLE, ECCPUBLICKEYBLOB *, BYTE *, ULONG, ECCSIGNATUREBLOB *);
typedef ULONG (*PFN_SKF_RSASignData)(HCONTAINER, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_RSAVerify)(DEVHANDLE, RSAPUBLICKEYBLOB *, BYTE *, ULONG, BYTE *, ULONG);
typedef ULONG (*PFN_SKF_ExtECCEncrypt)(DEVHANDLE, ECCPUBLICKEYBLOB *, BYTE *, ULONG, ECCCIPHERBLOB *);
typedef ULONG (*PFN_SKF_ECCDecrypt)(HCONTAINER, ULONG, ECCCIPHERBLOB *, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_ExtRSAPubKeyOperation)(DEVHANDLE, RSAPUBLICKEYBLOB *, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_RSADecrypt)(HCONTAINER, ULONG, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_SetSymmKey)(DEVHANDLE, BYTE *, ULONG, HANDLE *);
typedef ULONG (*PFN_SKF_EncryptInit)(HANDLE, BLOCKCIPHERPARAM);
typedef ULONG (*PFN_SKF_Encrypt)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_DecryptInit)(HANDLE, BLOCKCIPHERPARAM);
typedef ULONG (*PFN_SKF_Decrypt)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_Mac)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_DigestInit)(DEVHANDLE, ULONG, ECCPUBLICKEYBLOB *, BYTE *, ULONG, HANDLE *);
typedef ULONG (*PFN_SKF_Digest)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_CloseHandle)(HANDLE);
typedef ULONG (*PFN_SKF_CreateFile)(HAPPLICATION, LPSTR, ULONG, ULONG, ULONG);
typedef ULONG (*PFN_SKF_DeleteFile)(HAPPLICATION, LPSTR);
typedef ULONG (*PFN_SKF_ReadFile)(HAPPLICATION, LPSTR, ULONG, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_WriteFile)(HAPPLICATION, LPSTR, ULONG, BYTE *, ULONG);
typedef ULONG (*PFN_SKF_GenerateKeyPairKyber)(DEVHANDLE, ULONG, ULONG, KyberPublicKey *, KyberPrivateKey *);
typedef ULONG (*PFN_SKF_Encap_Kyber)(DEVHANDLE, ULONG, KyberPublicKey *, ULONG, BYTE *, ULONG *, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_Decap_Kyber)(DEVHANDLE, BYTE *, ULONG, ULONG, KyberPrivateKey *, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_GenerateKeyPair_Dilithium)(DEVHANDLE, ULONG, ULONG, DilithiumPublicKey *, DilithiumPrivateKey *);
typedef ULONG (*PFN_SKF_Sign_Dilithium)(DEVHANDLE, BYTE *, ULONG, ULONG, DilithiumPrivateKey *, BYTE *, ULONG, ULONG, ULONG, ULONG, ULONG, BYTE *, ULONG *);
typedef ULONG (*PFN_SKF_Verify_Dilithium)(DEVHANDLE, ULONG, DilithiumPublicKey *, BYTE *, ULONG, ULONG, ULONG, ULONG, BYTE *, ULONG, BYTE *, ULONG);

typedef struct {
    void *lib;
    PFN_SKF_EnumDev SKF_EnumDev;
    PFN_SKF_ConnectDev SKF_ConnectDev;
    PFN_SKF_DisConnectDev SKF_DisConnectDev;
    PFN_SKF_GetDevInfo SKF_GetDevInfo;
    PFN_SKF_GenRandom SKF_GenRandom;
    PFN_SKF_OpenApplication SKF_OpenApplication;
    PFN_SKF_CloseApplication SKF_CloseApplication;
    PFN_SKF_VerifyPIN SKF_VerifyPIN;
    PFN_SKF_CreateContainer SKF_CreateContainer;
    PFN_SKF_DeleteContainer SKF_DeleteContainer;
    PFN_SKF_OpenContainer SKF_OpenContainer;
    PFN_SKF_CloseContainer SKF_CloseContainer;
    PFN_SKF_GenECCKeyPair SKF_GenECCKeyPair;
    PFN_SKF_GenRSAKeyPair SKF_GenRSAKeyPair;
    PFN_SKF_ExportPublicKey SKF_ExportPublicKey;
    PFN_SKF_ECCSignData SKF_ECCSignData;
    PFN_SKF_ECCVerify SKF_ECCVerify;
    PFN_SKF_RSASignData SKF_RSASignData;
    PFN_SKF_RSAVerify SKF_RSAVerify;
    PFN_SKF_ExtECCEncrypt SKF_ExtECCEncrypt;
    PFN_SKF_ECCDecrypt SKF_ECCDecrypt;
    PFN_SKF_ExtRSAPubKeyOperation SKF_ExtRSAPubKeyOperation;
    PFN_SKF_RSADecrypt SKF_RSADecrypt;
    PFN_SKF_SetSymmKey SKF_SetSymmKey;
    PFN_SKF_EncryptInit SKF_EncryptInit;
    PFN_SKF_Encrypt SKF_Encrypt;
    PFN_SKF_DecryptInit SKF_DecryptInit;
    PFN_SKF_Decrypt SKF_Decrypt;
    PFN_SKF_Mac SKF_Mac;
    PFN_SKF_DigestInit SKF_DigestInit;
    PFN_SKF_Digest SKF_Digest;
    PFN_SKF_CloseHandle SKF_CloseHandle;
    PFN_SKF_CreateFile SKF_CreateFile;
    PFN_SKF_DeleteFile SKF_DeleteFile;
    PFN_SKF_ReadFile SKF_ReadFile;
    PFN_SKF_WriteFile SKF_WriteFile;
    PFN_SKF_GenerateKeyPairKyber SKF_GenerateKeyPairKyber;
    PFN_SKF_Encap_Kyber SKF_Encap_Kyber;
    PFN_SKF_Decap_Kyber SKF_Decap_Kyber;
    PFN_SKF_GenerateKeyPair_Dilithium SKF_GenerateKeyPair_Dilithium;
    PFN_SKF_Sign_Dilithium SKF_Sign_Dilithium;
    PFN_SKF_Verify_Dilithium SKF_Verify_Dilithium;
} skf_runtime_t;

typedef struct {
    DEVHANDLE dev;
    HAPPLICATION app;
    HCONTAINER container;
} skf_session_t;

static const char *last_dl_error(void) {
    const char *msg = dlerror();
    return msg != NULL ? msg : "unknown dlerror";
}

static int load_symbol(void *lib, const char *name, void *fn_out, int required, char *errbuf, size_t errbuf_sz) {
    void *sym;
    dlerror();
    sym = dlsym(lib, name);
    if (sym == NULL) {
        if (required) {
            snprintf(errbuf, errbuf_sz, "missing SKF symbol %s: %s", name, last_dl_error());
            return -1;
        }
        memset(fn_out, 0, sizeof(sym));
        return 0;
    }
    memcpy(fn_out, &sym, sizeof(sym));
    return 0;
}

#define LOAD_REQ(rt, fn) do { if (load_symbol((rt)->lib, #fn, &(rt)->fn, 1, errbuf, errbuf_sz) != 0) return -1; } while (0)
#define LOAD_OPT(rt, fn) do { if (load_symbol((rt)->lib, #fn, &(rt)->fn, 0, errbuf, errbuf_sz) != 0) return -1; } while (0)

static int missing_symbol(const char *name, char *errbuf, size_t errbuf_sz) {
    snprintf(errbuf, errbuf_sz, "GM3000 SKF library does not export required symbol %s", name);
    return -1;
}

static const char *env_or_default(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

static int streq(const char *a, const char *b) {
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

static int starts_with(const char *s, const char *prefix) {
    return s != NULL && strncmp(s, prefix, strlen(prefix)) == 0;
}

static void fill_common(const device_resource_t *device, const translated_call_t *call, response_t *resp) {
    snprintf(resp->selected_device, sizeof(resp->selected_device), "%s", device->device_id);
    snprintf(resp->backend_name, sizeof(resp->backend_name), "%s", call->backend_name);
    snprintf(resp->backend_call, sizeof(resp->backend_call), "%s", call->backend_call_name);
}

static int hex_digit(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *hex, BYTE *out, ULONG out_cap, ULONG *out_len) {
    ULONG len = 0U;
    int hi;
    int lo;
    if (hex == NULL) return -1;
    while (*hex != '\0') {
        while (*hex == ' ' || *hex == ':' || *hex == '-') hex++;
        if (*hex == '\0') break;
        hi = hex_digit((unsigned char)*hex++);
        if (*hex == '\0') return -1;
        lo = hex_digit((unsigned char)*hex++);
        if (hi < 0 || lo < 0 || len >= out_cap) return -1;
        out[len++] = (BYTE)((hi << 4) | lo);
    }
    *out_len = len;
    return 0;
}

static int input_to_bytes(const char *text, BYTE *out, ULONG out_cap, ULONG *out_len) {
    size_t len;
    if (text == NULL) {
        *out_len = 0U;
        return 0;
    }
    if (starts_with(text, "hex:")) {
        return decode_hex(text + 4, out, out_cap, out_len);
    }
    len = strlen(text);
    if (len > out_cap) return -1;
    memcpy(out, text, len);
    *out_len = (ULONG)len;
    return 0;
}

static void bytes_to_hex(const BYTE *in, ULONG in_len, char *out, size_t out_sz) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    size_t pos = 0U;
    if (out_sz == 0U) return;
    for (i = 0U; i < (size_t)in_len && pos + 2U < out_sz; ++i) {
        out[pos++] = hex[(in[i] >> 4) & 0x0FU];
        out[pos++] = hex[in[i] & 0x0FU];
    }
    out[pos] = '\0';
}

static int parse_ulong(const char *text, ULONG fallback, ULONG *out) {
    unsigned long value;
    char *end = NULL;
    if (text == NULL || text[0] == '\0') {
        *out = fallback;
        return 0;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text) return -1;
    *out = (ULONG)value;
    return 0;
}

static ULONG alg_to_skf_id(const char *algorithm) {
    if (streq(algorithm, "sm3")) return SGD_SM3;
    if (streq(algorithm, "sha256")) return SGD_SHA256;
    if (streq(algorithm, "sm2") || streq(algorithm, "sm2-sign")) return SGD_SM2_1;
    if (streq(algorithm, "sm2-enc")) return SGD_SM2_3;
    if (streq(algorithm, "rsa") || streq(algorithm, "rsa-sign")) return SGD_RSA_SIGN;
    if (streq(algorithm, "rsa-enc")) return SGD_RSA_ENC;
    if (streq(algorithm, "sm4") || streq(algorithm, "sm4-cbc")) return SGD_SM4_CBC;
    if (streq(algorithm, "sm4-ecb")) return SGD_SM4_ECB;
    return 0U;
}

static int split_pair(const char *text, char *left, size_t left_sz, char *right, size_t right_sz) {
    const char *sep;
    size_t n;
    if (text == NULL) return -1;
    sep = strchr(text, '|');
    if (sep == NULL) return -1;
    n = (size_t)(sep - text);
    if (n >= left_sz) return -1;
    memcpy(left, text, n);
    left[n] = '\0';
    snprintf(right, right_sz, "%s", sep + 1);
    return 0;
}

static int blob_from_hex(const char *text, void *blob, ULONG blob_sz, ULONG *actual_len) {
    ULONG len = 0U;
    memset(blob, 0, blob_sz);
    if (text == NULL || text[0] == '\0') return -1;
    if (starts_with(text, "hex:")) text += 4;
    if (decode_hex(text, (BYTE *)blob, blob_sz, &len) != 0) return -1;
    if (actual_len != NULL) *actual_len = len;
    return 0;
}

static int open_runtime(skf_runtime_t *rt, char *errbuf, size_t errbuf_sz) {
    const char *lib_path = env_or_default("GM3000_SKF_LIB", GM3000_DEFAULT_LIB);
    memset(rt, 0, sizeof(*rt));
    rt->lib = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if (rt->lib == NULL) {
        snprintf(errbuf, errbuf_sz, "dlopen %s failed: %s", lib_path, last_dl_error());
        return -1;
    }
    LOAD_REQ(rt, SKF_EnumDev);
    LOAD_REQ(rt, SKF_ConnectDev);
    LOAD_REQ(rt, SKF_DisConnectDev);
    LOAD_REQ(rt, SKF_GetDevInfo);
    LOAD_REQ(rt, SKF_GenRandom);
    LOAD_OPT(rt, SKF_OpenApplication);
    LOAD_OPT(rt, SKF_CloseApplication);
    LOAD_OPT(rt, SKF_VerifyPIN);
    LOAD_OPT(rt, SKF_CreateContainer);
    LOAD_OPT(rt, SKF_DeleteContainer);
    LOAD_OPT(rt, SKF_OpenContainer);
    LOAD_OPT(rt, SKF_CloseContainer);
    LOAD_OPT(rt, SKF_GenECCKeyPair);
    LOAD_OPT(rt, SKF_GenRSAKeyPair);
    LOAD_OPT(rt, SKF_ExportPublicKey);
    LOAD_OPT(rt, SKF_ECCSignData);
    LOAD_OPT(rt, SKF_ECCVerify);
    LOAD_OPT(rt, SKF_RSASignData);
    LOAD_OPT(rt, SKF_RSAVerify);
    LOAD_OPT(rt, SKF_ExtECCEncrypt);
    LOAD_OPT(rt, SKF_ECCDecrypt);
    LOAD_OPT(rt, SKF_ExtRSAPubKeyOperation);
    LOAD_OPT(rt, SKF_RSADecrypt);
    LOAD_OPT(rt, SKF_SetSymmKey);
    LOAD_OPT(rt, SKF_EncryptInit);
    LOAD_OPT(rt, SKF_Encrypt);
    LOAD_OPT(rt, SKF_DecryptInit);
    LOAD_OPT(rt, SKF_Decrypt);
    LOAD_OPT(rt, SKF_Mac);
    LOAD_OPT(rt, SKF_DigestInit);
    LOAD_OPT(rt, SKF_Digest);
    LOAD_OPT(rt, SKF_CloseHandle);
    LOAD_OPT(rt, SKF_CreateFile);
    LOAD_OPT(rt, SKF_DeleteFile);
    LOAD_OPT(rt, SKF_ReadFile);
    LOAD_OPT(rt, SKF_WriteFile);
    LOAD_OPT(rt, SKF_GenerateKeyPairKyber);
    LOAD_OPT(rt, SKF_Encap_Kyber);
    LOAD_OPT(rt, SKF_Decap_Kyber);
    LOAD_OPT(rt, SKF_GenerateKeyPair_Dilithium);
    LOAD_OPT(rt, SKF_Sign_Dilithium);
    LOAD_OPT(rt, SKF_Verify_Dilithium);
    return 0;
}

static void close_runtime(skf_runtime_t *rt) {
    if (rt != NULL && rt->lib != NULL) {
        dlclose(rt->lib);
        rt->lib = NULL;
    }
}

static int enum_first_device(skf_runtime_t *rt, char *name, size_t name_sz, char *errbuf, size_t errbuf_sz) {
    ULONG rv;
    ULONG len = 0U;
    char *buf;
    rv = rt->SKF_EnumDev(TRUE, NULL, &len);
    if (rv != SAR_OK || len == 0U) {
        snprintf(errbuf, errbuf_sz, "SKF_EnumDev length failed rv=0x%08X len=%u", rv, len);
        return -1;
    }
    buf = (char *)calloc((size_t)len + 1U, 1U);
    if (buf == NULL) {
        snprintf(errbuf, errbuf_sz, "out of memory enumerating SKF devices");
        return -1;
    }
    rv = rt->SKF_EnumDev(TRUE, buf, &len);
    if (rv != SAR_OK || buf[0] == '\0') {
        free(buf);
        snprintf(errbuf, errbuf_sz, "SKF_EnumDev failed rv=0x%08X", rv);
        return -1;
    }
    snprintf(name, name_sz, "%s", buf);
    free(buf);
    return 0;
}

static int open_device(skf_runtime_t *rt, skf_session_t *sess, char *errbuf, size_t errbuf_sz) {
    const char *configured_name = getenv("GM3000_SKF_DEVICE");
    char enum_name[GM3000_MAX_NAME];
    LPSTR dev_name;
    ULONG rv;
    memset(sess, 0, sizeof(*sess));
    if (configured_name != NULL && configured_name[0] != '\0') {
        dev_name = (LPSTR)configured_name;
    } else {
        if (enum_first_device(rt, enum_name, sizeof(enum_name), errbuf, errbuf_sz) != 0) return -1;
        dev_name = enum_name;
    }
    rv = rt->SKF_ConnectDev(dev_name, &sess->dev);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_ConnectDev(%s) failed rv=0x%08X", dev_name, rv);
        return -1;
    }
    return 0;
}

static int open_app(skf_runtime_t *rt, skf_session_t *sess, char *errbuf, size_t errbuf_sz) {
    const char *app_name = getenv("GM3000_SKF_APP");
    ULONG rv;
    if (rt->SKF_OpenApplication == NULL) return missing_symbol("SKF_OpenApplication", errbuf, errbuf_sz);
    if (app_name == NULL || app_name[0] == '\0') {
        snprintf(errbuf, errbuf_sz, "GM3000_SKF_APP is required for this operation");
        return -1;
    }
    rv = rt->SKF_OpenApplication(sess->dev, (LPSTR)app_name, &sess->app);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_OpenApplication(%s) failed rv=0x%08X", app_name, rv);
        return -1;
    }
    return 0;
}

static const char *container_name_from_call(const translated_call_t *call) {
    const char *env_name = getenv("GM3000_SKF_CONTAINER");
    if (call->call.key_ref[0] != '\0') return call->call.key_ref;
    if (env_name != NULL && env_name[0] != '\0') return env_name;
    return "default";
}

static int open_container(skf_runtime_t *rt, skf_session_t *sess, const translated_call_t *call, char *errbuf, size_t errbuf_sz) {
    const char *name = container_name_from_call(call);
    ULONG rv;
    if (rt->SKF_OpenContainer == NULL) return missing_symbol("SKF_OpenContainer", errbuf, errbuf_sz);
    rv = rt->SKF_OpenContainer(sess->app, (LPSTR)name, &sess->container);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_OpenContainer(%s) failed rv=0x%08X", name, rv);
        return -1;
    }
    return 0;
}

static int verify_pin_if_set(skf_runtime_t *rt, skf_session_t *sess, char *errbuf, size_t errbuf_sz) {
    const char *pin = getenv("GM3000_SKF_PIN");
    ULONG retry = 0U;
    ULONG rv;
    if (pin == NULL || pin[0] == '\0') return 0;
    if (rt->SKF_VerifyPIN == NULL) return missing_symbol("SKF_VerifyPIN", errbuf, errbuf_sz);
    rv = rt->SKF_VerifyPIN(sess->app, USER_TYPE, (LPSTR)pin, &retry);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_VerifyPIN failed rv=0x%08X retry=%u", rv, retry);
        return -1;
    }
    return 0;
}

static void close_session(skf_runtime_t *rt, skf_session_t *sess) {
    if (rt == NULL || sess == NULL) return;
    if (sess->container != NULL && rt->SKF_CloseContainer != NULL) {
        (void)rt->SKF_CloseContainer(sess->container);
        sess->container = NULL;
    }
    if (sess->app != NULL && rt->SKF_CloseApplication != NULL) {
        (void)rt->SKF_CloseApplication(sess->app);
        sess->app = NULL;
    }
    if (sess->dev != NULL) {
        (void)rt->SKF_DisConnectDev(sess->dev);
        sess->dev = NULL;
    }
}

static int open_base(skf_runtime_t *rt, skf_session_t *sess, char *errbuf, size_t errbuf_sz) {
    if (open_runtime(rt, errbuf, errbuf_sz) != 0) return -1;
    if (open_device(rt, sess, errbuf, errbuf_sz) != 0) {
        close_runtime(rt);
        return -1;
    }
    return 0;
}

static int open_app_container(skf_runtime_t *rt, skf_session_t *sess, const translated_call_t *call, int verify_pin, char *errbuf, size_t errbuf_sz) {
    if (open_base(rt, sess, errbuf, errbuf_sz) != 0) return -1;
    if (open_app(rt, sess, errbuf, errbuf_sz) != 0) goto fail;
    if (verify_pin && verify_pin_if_set(rt, sess, errbuf, errbuf_sz) != 0) goto fail;
    if (open_container(rt, sess, call, errbuf, errbuf_sz) != 0) goto fail;
    return 0;
fail:
    close_session(rt, sess);
    close_runtime(rt);
    return -1;
}

static int finalize_error_or_success(int rc, skf_runtime_t *rt, skf_session_t *sess) {
    close_session(rt, sess);
    close_runtime(rt);
    return rc;
}

static int gm3000_device_manage(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    int rc = -1;
    fill_common(device, call, resp);
    if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
    if (call->call.action == ACTION_GET_DEVICE_INFO) {
        DEVINFO info;
        ULONG rv;
        memset(&info, 0, sizeof(info));
        rv = rt.SKF_GetDevInfo(sess.dev, &info);
        if (rv == SAR_OK) {
            snprintf(resp->result, sizeof(resp->result), "gm3000-device(label=%.*s,serial=%.*s,manufacturer=%.*s)", (int)sizeof(info.Label), info.Label, (int)sizeof(info.SerialNumber), info.SerialNumber, (int)sizeof(info.Manufacturer), info.Manufacturer);
            rc = 0;
        } else {
            snprintf(errbuf, errbuf_sz, "SKF_GetDevInfo failed rv=0x%08X", rv);
        }
    } else if (call->call.action == ACTION_GENERATE_RANDOM) {
        BYTE out[GM3000_MAX_IO];
        ULONG out_len;
        ULONG rv;
        char hex[GM3000_RESULT_HEX];
        if (parse_ulong(call->call.payload, 16U, &out_len) != 0 || out_len > GM3000_MAX_IO) {
            snprintf(errbuf, errbuf_sz, "invalid random length payload=%s", call->call.payload);
        } else {
            rv = rt.SKF_GenRandom(sess.dev, out, out_len);
            if (rv == SAR_OK) {
                bytes_to_hex(out, out_len, hex, sizeof(hex));
                snprintf(resp->result, sizeof(resp->result), "gm3000-random(%u,%s)", out_len, hex);
                rc = 0;
            } else {
                snprintf(errbuf, errbuf_sz, "SKF_GenRandom failed rv=0x%08X", rv);
            }
        }
    } else {
        snprintf(errbuf, errbuf_sz, "unsupported gm3000 device action=%s", action_to_string(call->call.action));
    }
    return finalize_error_or_success(rc, &rt, &sess);
}

static int key_access(skf_runtime_t *rt, skf_session_t *sess, response_t *resp, char *errbuf, size_t errbuf_sz) {
    const char *pin = getenv("GM3000_SKF_PIN");
    ULONG retry = 0U;
    ULONG rv;
    if (rt->SKF_VerifyPIN == NULL) return missing_symbol("SKF_VerifyPIN", errbuf, errbuf_sz);
    if (pin == NULL || pin[0] == '\0') {
        snprintf(errbuf, errbuf_sz, "GM3000_SKF_PIN is required for get_private_key_access");
        return -1;
    }
    rv = rt->SKF_VerifyPIN(sess->app, USER_TYPE, (LPSTR)pin, &retry);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_VerifyPIN failed rv=0x%08X retry=%u", rv, retry);
        return -1;
    }
    snprintf(resp->result, sizeof(resp->result), "gm3000-key-access-ok(retry=%u)", retry);
    return 0;
}

static int key_generate_pair(skf_runtime_t *rt, skf_session_t *sess, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    char hex[GM3000_RESULT_HEX];
    ULONG rv;
    if (streq(call->call.algorithm, "sm2")) {
        ECCPUBLICKEYBLOB pub;
        if (rt->SKF_GenECCKeyPair == NULL) return missing_symbol("SKF_GenECCKeyPair", errbuf, errbuf_sz);
        memset(&pub, 0, sizeof(pub));
        rv = rt->SKF_GenECCKeyPair(sess->container, SGD_SM2_1, &pub);
        if (rv != SAR_OK) {
            snprintf(errbuf, errbuf_sz, "SKF_GenECCKeyPair failed rv=0x%08X", rv);
            return -1;
        }
        bytes_to_hex((BYTE *)&pub, (ULONG)sizeof(pub), hex, sizeof(hex));
        snprintf(resp->result, sizeof(resp->result), "gm3000-keypair(sm2,pub=hex:%s)", hex);
        return 0;
    }
    if (streq(call->call.algorithm, "rsa")) {
        RSAPUBLICKEYBLOB pub;
        ULONG bits;
        if (rt->SKF_GenRSAKeyPair == NULL) return missing_symbol("SKF_GenRSAKeyPair", errbuf, errbuf_sz);
        if (parse_ulong(call->call.payload, 2048U, &bits) != 0) bits = 2048U;
        memset(&pub, 0, sizeof(pub));
        rv = rt->SKF_GenRSAKeyPair(sess->container, bits, &pub);
        if (rv != SAR_OK) {
            snprintf(errbuf, errbuf_sz, "SKF_GenRSAKeyPair failed rv=0x%08X", rv);
            return -1;
        }
        bytes_to_hex((BYTE *)&pub, (ULONG)sizeof(pub), hex, sizeof(hex));
        snprintf(resp->result, sizeof(resp->result), "gm3000-keypair(rsa,pub=hex:%s)", hex);
        return 0;
    }
    return missing_symbol("PQC key-pair function for requested algorithm", errbuf, errbuf_sz);
}

static int gm3000_key_manage(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    int rc = -1;
    fill_common(device, call, resp);
    if (call->call.action == ACTION_GET_PRIVATE_KEY_ACCESS || call->call.action == ACTION_RELEASE_PRIVATE_KEY_ACCESS || call->call.action == ACTION_DESTROY_KEY) {
        if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
        if (open_app(&rt, &sess, errbuf, errbuf_sz) != 0) return finalize_error_or_success(-1, &rt, &sess);
    } else {
        if (open_app_container(&rt, &sess, call, 1, errbuf, errbuf_sz) != 0) return -1;
    }
    switch (call->call.action) {
        case ACTION_GET_PRIVATE_KEY_ACCESS:
            rc = key_access(&rt, &sess, resp, errbuf, errbuf_sz);
            break;
        case ACTION_RELEASE_PRIVATE_KEY_ACCESS:
            snprintf(resp->result, sizeof(resp->result), "%s", "gm3000-key-access-released");
            rc = 0;
            break;
        case ACTION_GENERATE_KEY_PAIR:
            rc = key_generate_pair(&rt, &sess, call, resp, errbuf, errbuf_sz);
            break;
        case ACTION_EXPORT_PUBLIC_KEY: {
            BYTE out[GM3000_MAX_IO];
            ULONG out_len = sizeof(out);
            ULONG rv;
            char hex[GM3000_RESULT_HEX];
            if (rt.SKF_ExportPublicKey == NULL) { rc = missing_symbol("SKF_ExportPublicKey", errbuf, errbuf_sz); break; }
            rv = rt.SKF_ExportPublicKey(sess.container, TRUE, out, &out_len);
            if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ExportPublicKey failed rv=0x%08X", rv);
            else { bytes_to_hex(out, out_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-export-public-key(hex:%s)", hex); rc = 0; }
            break;
        }
        case ACTION_IMPORT_KEY: {
            BYTE key[GM3000_MAX_IO];
            ULONG key_len = 0U;
            HANDLE handle = NULL;
            ULONG alg = alg_to_skf_id(call->call.algorithm);
            ULONG rv;
            if (rt.SKF_SetSymmKey == NULL) { rc = missing_symbol("SKF_SetSymmKey", errbuf, errbuf_sz); break; }
            if (alg == 0U) alg = SGD_SM4_CBC;
            if (input_to_bytes(call->call.payload[0] != '\0' ? call->call.payload : call->call.aux_payload, key, sizeof(key), &key_len) != 0 || key_len == 0U) { snprintf(errbuf, errbuf_sz, "import_key requires key bytes in payload or aux_payload"); break; }
            rv = rt.SKF_SetSymmKey(sess.dev, key, alg, &handle);
            if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_SetSymmKey(import) failed rv=0x%08X", rv);
            else { if (rt.SKF_CloseHandle != NULL && handle != NULL) (void)rt.SKF_CloseHandle(handle); snprintf(resp->result, sizeof(resp->result), "gm3000-import-key(transient,%u-bytes)", key_len); rc = 0; }
            break;
        }
        case ACTION_DESTROY_KEY: {
            const char *name = container_name_from_call(call);
            ULONG rv;
            if (rt.SKF_DeleteContainer == NULL) { rc = missing_symbol("SKF_DeleteContainer", errbuf, errbuf_sz); break; }
            rv = rt.SKF_DeleteContainer(sess.app, (LPSTR)name);
            if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_DeleteContainer(%s) failed rv=0x%08X", name, rv);
            else { snprintf(resp->result, sizeof(resp->result), "gm3000-destroy-key(%s)", name); rc = 0; }
            break;
        }
        default:
            snprintf(errbuf, errbuf_sz, "unsupported gm3000 key action=%s", action_to_string(call->call.action));
            break;
    }
    return finalize_error_or_success(rc, &rt, &sess);
}

static int gm3000_asym_crypto(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    BYTE input[GM3000_MAX_IO];
    ULONG input_len = 0U;
    int rc = -1;
    fill_common(device, call, resp);
    if (input_to_bytes(call->call.payload, input, sizeof(input), &input_len) != 0) {
        snprintf(errbuf, errbuf_sz, "invalid asym input payload");
        return -1;
    }
    if (call->call.action == ACTION_VERIFY || call->call.action == ACTION_ENCRYPT) {
        if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
    } else if (open_app_container(&rt, &sess, call, 1, errbuf, errbuf_sz) != 0) {
        return -1;
    }
    if (call->call.action == ACTION_SIGN && streq(call->call.algorithm, "sm2")) {
        ECCSIGNATUREBLOB sig;
        ULONG rv;
        char hex[sizeof(sig) * 2U + 1U];
        if (rt.SKF_ECCSignData == NULL) rc = missing_symbol("SKF_ECCSignData", errbuf, errbuf_sz);
        else {
            memset(&sig, 0, sizeof(sig));
            rv = rt.SKF_ECCSignData(sess.container, input, input_len, &sig);
            if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ECCSignData failed rv=0x%08X", rv);
            else { bytes_to_hex((BYTE *)&sig, (ULONG)sizeof(sig), hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-sign(sm2,hex:%s)", hex); rc = 0; }
        }
    } else if (call->call.action == ACTION_SIGN && streq(call->call.algorithm, "rsa")) {
        BYTE sig[GM3000_MAX_IO];
        ULONG sig_len = sizeof(sig);
        ULONG rv;
        char hex[GM3000_RESULT_HEX];
        if (rt.SKF_RSASignData == NULL) rc = missing_symbol("SKF_RSASignData", errbuf, errbuf_sz);
        else {
            rv = rt.SKF_RSASignData(sess.container, input, input_len, sig, &sig_len);
            if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_RSASignData failed rv=0x%08X", rv);
            else { bytes_to_hex(sig, sig_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-sign(rsa,hex:%s)", hex); rc = 0; }
        }
    } else if (call->call.action == ACTION_VERIFY) {
        char pub_hex[MAX_PAYLOAD_LEN];
        char sig_hex[MAX_PAYLOAD_LEN];
        if (split_pair(call->call.aux_payload, pub_hex, sizeof(pub_hex), sig_hex, sizeof(sig_hex)) != 0) snprintf(errbuf, errbuf_sz, "verify requires aux_payload pubkey_hex|signature_hex");
        else if (streq(call->call.algorithm, "sm2")) {
            ECCPUBLICKEYBLOB pub;
            ECCSIGNATUREBLOB sig;
            ULONG rv;
            if (rt.SKF_ECCVerify == NULL) rc = missing_symbol("SKF_ECCVerify", errbuf, errbuf_sz);
            else if (blob_from_hex(pub_hex, &pub, sizeof(pub), NULL) != 0 || blob_from_hex(sig_hex, &sig, sizeof(sig), NULL) != 0) snprintf(errbuf, errbuf_sz, "invalid SM2 public key or signature hex");
            else { rv = rt.SKF_ECCVerify(sess.dev, &pub, input, input_len, &sig); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ECCVerify failed rv=0x%08X", rv); else { snprintf(resp->result, sizeof(resp->result), "%s", "gm3000-verify-ok(sm2)"); rc = 0; } }
        } else if (streq(call->call.algorithm, "rsa")) {
            RSAPUBLICKEYBLOB pub;
            BYTE sig[GM3000_MAX_IO];
            ULONG sig_len = 0U;
            ULONG rv;
            if (rt.SKF_RSAVerify == NULL) rc = missing_symbol("SKF_RSAVerify", errbuf, errbuf_sz);
            else if (blob_from_hex(pub_hex, &pub, sizeof(pub), NULL) != 0 || blob_from_hex(sig_hex, sig, sizeof(sig), &sig_len) != 0) snprintf(errbuf, errbuf_sz, "invalid RSA public key or signature hex");
            else { rv = rt.SKF_RSAVerify(sess.dev, &pub, input, input_len, sig, sig_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_RSAVerify failed rv=0x%08X", rv); else { snprintf(resp->result, sizeof(resp->result), "%s", "gm3000-verify-ok(rsa)"); rc = 0; } }
        }
    } else if (call->call.action == ACTION_ENCRYPT && streq(call->call.algorithm, "sm2")) {
        ECCPUBLICKEYBLOB pub;
        ECCCIPHERBLOB cipher;
        ULONG rv;
        char hex[sizeof(cipher) * 2U + 1U];
        if (rt.SKF_ExtECCEncrypt == NULL) rc = missing_symbol("SKF_ExtECCEncrypt", errbuf, errbuf_sz);
        else if (blob_from_hex(call->call.aux_payload, &pub, sizeof(pub), NULL) != 0) snprintf(errbuf, errbuf_sz, "SM2 encrypt requires public key hex in aux_payload");
        else { memset(&cipher, 0, sizeof(cipher)); rv = rt.SKF_ExtECCEncrypt(sess.dev, &pub, input, input_len, &cipher); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ExtECCEncrypt failed rv=0x%08X", rv); else { bytes_to_hex((BYTE *)&cipher, (ULONG)sizeof(cipher), hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-cipher(sm2,hex:%s)", hex); rc = 0; } }
    } else if (call->call.action == ACTION_ENCRYPT && streq(call->call.algorithm, "rsa")) {
        RSAPUBLICKEYBLOB pub;
        BYTE out[GM3000_MAX_IO];
        ULONG out_len = sizeof(out);
        ULONG rv;
        char hex[GM3000_RESULT_HEX];
        if (rt.SKF_ExtRSAPubKeyOperation == NULL) rc = missing_symbol("SKF_ExtRSAPubKeyOperation", errbuf, errbuf_sz);
        else if (blob_from_hex(call->call.aux_payload, &pub, sizeof(pub), NULL) != 0) snprintf(errbuf, errbuf_sz, "RSA encrypt requires public key hex in aux_payload");
        else { rv = rt.SKF_ExtRSAPubKeyOperation(sess.dev, &pub, input, input_len, out, &out_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ExtRSAPubKeyOperation failed rv=0x%08X", rv); else { bytes_to_hex(out, out_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-cipher(rsa,hex:%s)", hex); rc = 0; } }
    } else if (call->call.action == ACTION_DECRYPT && streq(call->call.algorithm, "sm2")) {
        ECCCIPHERBLOB cipher;
        BYTE out[GM3000_MAX_IO];
        ULONG out_len = sizeof(out);
        ULONG rv;
        char hex[GM3000_RESULT_HEX];
        if (rt.SKF_ECCDecrypt == NULL) rc = missing_symbol("SKF_ECCDecrypt", errbuf, errbuf_sz);
        else if (blob_from_hex(call->call.payload, &cipher, sizeof(cipher), NULL) != 0) snprintf(errbuf, errbuf_sz, "SM2 decrypt requires cipher hex payload");
        else { rv = rt.SKF_ECCDecrypt(sess.container, SGD_SM2_3, &cipher, out, &out_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ECCDecrypt failed rv=0x%08X", rv); else { bytes_to_hex(out, out_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-plain(sm2,hex:%s)", hex); rc = 0; } }
    } else if (call->call.action == ACTION_DECRYPT && streq(call->call.algorithm, "rsa")) {
        BYTE out[GM3000_MAX_IO];
        ULONG out_len = sizeof(out);
        ULONG rv;
        char hex[GM3000_RESULT_HEX];
        if (rt.SKF_RSADecrypt == NULL) rc = missing_symbol("SKF_RSADecrypt", errbuf, errbuf_sz);
        else { rv = rt.SKF_RSADecrypt(sess.container, SGD_RSA_ENC, input, input_len, out, &out_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_RSADecrypt failed rv=0x%08X", rv); else { bytes_to_hex(out, out_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-plain(rsa,hex:%s)", hex); rc = 0; } }
    } else {
        snprintf(errbuf, errbuf_sz, "unsupported gm3000 asym action=%s alg=%s", action_to_string(call->call.action), call->call.algorithm);
    }
    return finalize_error_or_success(rc, &rt, &sess);
}

static int sym_key_bytes(const translated_call_t *call, BYTE *key, ULONG key_cap, ULONG *key_len) {
    const char *env_key = getenv("GM3000_SKF_SYM_KEY");
    const char *src = call->call.aux_payload[0] != '\0' ? call->call.aux_payload : env_key;
    return input_to_bytes(src, key, key_cap, key_len);
}

static int gm3000_sym_crypto(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    BYTE key[GM3000_MAX_IO];
    ULONG key_len = 0U;
    BYTE input[GM3000_MAX_IO];
    ULONG input_len = 0U;
    BYTE output[GM3000_MAX_IO];
    ULONG output_len = sizeof(output);
    HANDLE hkey = NULL;
    ULONG alg = alg_to_skf_id(call->call.algorithm);
    ULONG rv;
    int rc = -1;
    char hex[GM3000_RESULT_HEX];
    BLOCKCIPHERPARAM param;
    fill_common(device, call, resp);
    if (alg == 0U) alg = SGD_SM4_CBC;
    if (sym_key_bytes(call, key, sizeof(key), &key_len) != 0 || key_len == 0U) { snprintf(errbuf, errbuf_sz, "sym operation requires key bytes in aux_payload or GM3000_SKF_SYM_KEY"); return -1; }
    if (input_to_bytes(call->call.payload, input, sizeof(input), &input_len) != 0) { snprintf(errbuf, errbuf_sz, "invalid sym input payload"); return -1; }
    if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
    if (rt.SKF_SetSymmKey == NULL) { rc = missing_symbol("SKF_SetSymmKey", errbuf, errbuf_sz); goto done; }
    rv = rt.SKF_SetSymmKey(sess.dev, key, alg, &hkey);
    if (rv != SAR_OK) { snprintf(errbuf, errbuf_sz, "SKF_SetSymmKey failed rv=0x%08X", rv); goto done; }
    memset(&param, 0, sizeof(param));
    if (call->call.action == ACTION_ENCRYPT) {
        if (rt.SKF_EncryptInit == NULL || rt.SKF_Encrypt == NULL) { rc = missing_symbol("SKF_EncryptInit/SKF_Encrypt", errbuf, errbuf_sz); goto done; }
        rv = rt.SKF_EncryptInit(hkey, param);
        if (rv == SAR_OK) rv = rt.SKF_Encrypt(hkey, input, input_len, output, &output_len);
        if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Encrypt failed rv=0x%08X", rv);
        else { bytes_to_hex(output, output_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-sym-enc(hex:%s)", hex); rc = 0; }
    } else if (call->call.action == ACTION_DECRYPT) {
        if (rt.SKF_DecryptInit == NULL || rt.SKF_Decrypt == NULL) { rc = missing_symbol("SKF_DecryptInit/SKF_Decrypt", errbuf, errbuf_sz); goto done; }
        rv = rt.SKF_DecryptInit(hkey, param);
        if (rv == SAR_OK) rv = rt.SKF_Decrypt(hkey, input, input_len, output, &output_len);
        if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Decrypt failed rv=0x%08X", rv);
        else { bytes_to_hex(output, output_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-sym-dec(hex:%s)", hex); rc = 0; }
    } else if (call->call.action == ACTION_MAC) {
        if (rt.SKF_Mac == NULL) { rc = missing_symbol("SKF_Mac", errbuf, errbuf_sz); goto done; }
        rv = rt.SKF_Mac(hkey, input, input_len, output, &output_len);
        if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Mac failed rv=0x%08X", rv);
        else { bytes_to_hex(output, output_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-mac(hex:%s)", hex); rc = 0; }
    } else {
        snprintf(errbuf, errbuf_sz, "unsupported gm3000 sym action=%s", action_to_string(call->call.action));
    }
done:
    if (hkey != NULL && rt.SKF_CloseHandle != NULL) (void)rt.SKF_CloseHandle(hkey);
    return finalize_error_or_success(rc, &rt, &sess);
}

static int gm3000_hash_ops(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    BYTE input[GM3000_MAX_IO];
    ULONG input_len = 0U;
    BYTE digest[128];
    ULONG digest_len = sizeof(digest);
    HANDLE hhash = NULL;
    ULONG alg = alg_to_skf_id(call->call.algorithm);
    ULONG rv;
    int rc = -1;
    char hex[sizeof(digest) * 2U + 1U];
    fill_common(device, call, resp);
    if (alg == 0U) alg = SGD_SM3;
    if (input_to_bytes(call->call.payload, input, sizeof(input), &input_len) != 0) { snprintf(errbuf, errbuf_sz, "invalid hash input payload"); return -1; }
    if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
    if (rt.SKF_DigestInit == NULL || rt.SKF_Digest == NULL) { rc = missing_symbol("SKF_DigestInit/SKF_Digest", errbuf, errbuf_sz); goto done; }
    rv = rt.SKF_DigestInit(sess.dev, alg, NULL, NULL, 0, &hhash);
    if (rv == SAR_OK) rv = rt.SKF_Digest(hhash, input, input_len, digest, &digest_len);
    if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Digest failed rv=0x%08X", rv);
    else { bytes_to_hex(digest, digest_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-hash(%s,hex:%s)", call->call.algorithm, hex); rc = 0; }
done:
    if (hhash != NULL && rt.SKF_CloseHandle != NULL) (void)rt.SKF_CloseHandle(hhash);
    return finalize_error_or_success(rc, &rt, &sess);
}

static int gm3000_file_ops(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    const char *file_name = call->call.key_ref[0] != '\0' ? call->call.key_ref : call->call.payload;
    ULONG rv;
    int rc = -1;
    fill_common(device, call, resp);
    if (file_name == NULL || file_name[0] == '\0') { snprintf(errbuf, errbuf_sz, "file operation requires key_ref as file name"); return -1; }
    if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
    if (open_app(&rt, &sess, errbuf, errbuf_sz) != 0) return finalize_error_or_success(-1, &rt, &sess);
    if (call->call.action == ACTION_CREATE_FILE) {
        ULONG size;
        if (rt.SKF_CreateFile == NULL) rc = missing_symbol("SKF_CreateFile", errbuf, errbuf_sz);
        else if (parse_ulong(call->call.payload, 1024U, &size) != 0) snprintf(errbuf, errbuf_sz, "create_file payload must be file size");
        else { rv = rt.SKF_CreateFile(sess.app, (LPSTR)file_name, size, GM3000_DEFAULT_RIGHTS, GM3000_DEFAULT_RIGHTS); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_CreateFile failed rv=0x%08X", rv); else { snprintf(resp->result, sizeof(resp->result), "gm3000-create-file(%s,%u)", file_name, size); rc = 0; } }
    } else if (call->call.action == ACTION_READ_FILE) {
        BYTE out[GM3000_MAX_IO];
        ULONG want;
        ULONG out_len;
        char hex[GM3000_RESULT_HEX];
        if (rt.SKF_ReadFile == NULL) rc = missing_symbol("SKF_ReadFile", errbuf, errbuf_sz);
        else if (parse_ulong(call->call.payload, 256U, &want) != 0 || want > sizeof(out)) snprintf(errbuf, errbuf_sz, "read_file payload must be length <= %u", (ULONG)sizeof(out));
        else { out_len = want; rv = rt.SKF_ReadFile(sess.app, (LPSTR)file_name, 0U, want, out, &out_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_ReadFile failed rv=0x%08X", rv); else { bytes_to_hex(out, out_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-read-file(len=%u,hex:%s)", out_len, hex); rc = 0; } }
    } else if (call->call.action == ACTION_WRITE_FILE) {
        BYTE in[GM3000_MAX_IO];
        ULONG in_len = 0U;
        if (rt.SKF_WriteFile == NULL) rc = missing_symbol("SKF_WriteFile", errbuf, errbuf_sz);
        else if (input_to_bytes(call->call.payload, in, sizeof(in), &in_len) != 0) snprintf(errbuf, errbuf_sz, "write_file payload too large or invalid hex");
        else { rv = rt.SKF_WriteFile(sess.app, (LPSTR)file_name, 0U, in, in_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_WriteFile failed rv=0x%08X", rv); else { snprintf(resp->result, sizeof(resp->result), "gm3000-write-file(%s,%u-bytes)", file_name, in_len); rc = 0; } }
    } else if (call->call.action == ACTION_DELETE_FILE) {
        if (rt.SKF_DeleteFile == NULL) rc = missing_symbol("SKF_DeleteFile", errbuf, errbuf_sz);
        else { rv = rt.SKF_DeleteFile(sess.app, (LPSTR)file_name); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_DeleteFile failed rv=0x%08X", rv); else { snprintf(resp->result, sizeof(resp->result), "gm3000-delete-file(%s)", file_name); rc = 0; } }
    } else {
        snprintf(errbuf, errbuf_sz, "unsupported gm3000 file action=%s", action_to_string(call->call.action));
    }
    return finalize_error_or_success(rc, &rt, &sess);
}

static int gm3000_pqc_ops(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    skf_runtime_t rt;
    skf_session_t sess;
    BYTE input[GM3000_MAX_IO];
    ULONG input_len = 0U;
    BYTE output[GM3000_MAX_IO];
    ULONG output_len = sizeof(output);
    ULONG rv;
    int rc = -1;
    char hex[GM3000_RESULT_HEX];
    fill_common(device, call, resp);
    if (input_to_bytes(call->call.payload, input, sizeof(input), &input_len) != 0) { snprintf(errbuf, errbuf_sz, "invalid pqc input payload"); return -1; }
    if (open_base(&rt, &sess, errbuf, errbuf_sz) != 0) return -1;
    if (call->call.action == ACTION_KEM_ENCAP) {
        KyberPublicKey pub;
        BYTE shared[128];
        ULONG shared_len = sizeof(shared);
        char shared_hex[sizeof(shared) * 2U + 1U];
        if (rt.SKF_Encap_Kyber == NULL) rc = missing_symbol("SKF_Encap_Kyber", errbuf, errbuf_sz);
        else if (blob_from_hex(call->call.aux_payload, &pub, sizeof(pub), NULL) != 0) snprintf(errbuf, errbuf_sz, "KEM encap requires KyberPublicKey hex in aux_payload");
        else { rv = rt.SKF_Encap_Kyber(sess.dev, 0U, &pub, 0U, output, &output_len, shared, &shared_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Encap_Kyber failed rv=0x%08X", rv); else { bytes_to_hex(output, output_len, hex, sizeof(hex)); bytes_to_hex(shared, shared_len, shared_hex, sizeof(shared_hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-kem-ct(hex:%s)|ss(hex:%s)", hex, shared_hex); rc = 0; } }
    } else if (call->call.action == ACTION_KEM_DECAP) {
        KyberPrivateKey pri;
        if (rt.SKF_Decap_Kyber == NULL) rc = missing_symbol("SKF_Decap_Kyber", errbuf, errbuf_sz);
        else if (blob_from_hex(call->call.aux_payload, &pri, sizeof(pri), NULL) != 0) snprintf(errbuf, errbuf_sz, "KEM decap requires KyberPrivateKey hex in aux_payload");
        else { rv = rt.SKF_Decap_Kyber(sess.dev, input, input_len, 0U, &pri, 0U, output, &output_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Decap_Kyber failed rv=0x%08X", rv); else { bytes_to_hex(output, output_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-kem-ss(hex:%s)", hex); rc = 0; } }
    } else if (call->call.action == ACTION_SIGN) {
        DilithiumPrivateKey pri;
        if (rt.SKF_Sign_Dilithium == NULL) rc = missing_symbol("SKF_Sign_Dilithium", errbuf, errbuf_sz);
        else if (blob_from_hex(call->call.aux_payload, &pri, sizeof(pri), NULL) != 0) snprintf(errbuf, errbuf_sz, "Dilithium sign requires private key hex in aux_payload");
        else { rv = rt.SKF_Sign_Dilithium(sess.dev, input, input_len, 0U, &pri, NULL, 0U, SGD_SM3, 32U, 0U, 0U, output, &output_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Sign_Dilithium failed rv=0x%08X", rv); else { bytes_to_hex(output, output_len, hex, sizeof(hex)); snprintf(resp->result, sizeof(resp->result), "gm3000-pqc-sign(hex:%s)", hex); rc = 0; } }
    } else if (call->call.action == ACTION_VERIFY) {
        char pub_hex[MAX_PAYLOAD_LEN];
        char sig_hex[MAX_PAYLOAD_LEN];
        DilithiumPublicKey pub;
        BYTE sig[GM3000_MAX_IO];
        ULONG sig_len = 0U;
        if (rt.SKF_Verify_Dilithium == NULL) rc = missing_symbol("SKF_Verify_Dilithium", errbuf, errbuf_sz);
        else if (split_pair(call->call.aux_payload, pub_hex, sizeof(pub_hex), sig_hex, sizeof(sig_hex)) != 0) snprintf(errbuf, errbuf_sz, "Dilithium verify requires aux_payload pubkey_hex|signature_hex");
        else if (blob_from_hex(pub_hex, &pub, sizeof(pub), NULL) != 0 || blob_from_hex(sig_hex, sig, sizeof(sig), &sig_len) != 0) snprintf(errbuf, errbuf_sz, "invalid Dilithium public key or signature hex");
        else { rv = rt.SKF_Verify_Dilithium(sess.dev, 0U, &pub, NULL, 0U, SGD_SM3, 32U, 0U, input, input_len, sig, sig_len); if (rv != SAR_OK) snprintf(errbuf, errbuf_sz, "SKF_Verify_Dilithium failed rv=0x%08X", rv); else { snprintf(resp->result, sizeof(resp->result), "%s", "gm3000-pqc-verify-ok"); rc = 0; } }
    } else {
        snprintf(errbuf, errbuf_sz, "unsupported gm3000 pqc action=%s", action_to_string(call->call.action));
    }
    return finalize_error_or_success(rc, &rt, &sess);
}

driver_ops_t skf_driver_ops(void) {
    driver_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.device_manage = gm3000_device_manage;
    ops.key_manage = gm3000_key_manage;
    ops.asym_crypto = gm3000_asym_crypto;
    ops.sym_crypto = gm3000_sym_crypto;
    ops.hash_ops = gm3000_hash_ops;
    ops.file_ops = gm3000_file_ops;
    ops.pqc_ops = gm3000_pqc_ops;
    return ops;
}
