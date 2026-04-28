#include "driver.h"
#include "protocol.h"
#include "skfapi.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GM3000_DEFAULT_LIB "./vendor/libgm3000.1.0.so"
#define GM3000_MAX_IO 512U

typedef struct {
    void *lib;
    SKF_EnumDev_Fn SKF_EnumDev;
    SKF_ConnectDev_Fn SKF_ConnectDev;
    SKF_DisConnectDev_Fn SKF_DisConnectDev;
    SKF_GetDevInfo_Fn SKF_GetDevInfo;
    SKF_GenRandom_Fn SKF_GenRandom;
    SKF_DigestInit_Fn SKF_DigestInit;
    SKF_Digest_Fn SKF_Digest;
    SKF_CloseHandle_Fn SKF_CloseHandle;
} gm3000_runtime_t;

typedef struct {
    DEVHANDLE dev;
} gm3000_session_t;

static const char *last_dl_error(void) {
    const char *msg = dlerror();
    return msg ? msg : "unknown dlerror";
}

static int load_symbol(void *lib, const char *name, void *fn_out) {
    void *sym;
    dlerror();
    sym = dlsym(lib, name);
    if (sym == NULL) {
        return -1;
    }
    memcpy(fn_out, &sym, sizeof(sym));
    return 0;
}

#define LOAD_SYMBOL(rt, name) do { \
    if (load_symbol((rt)->lib, #name, &(rt)->name) != 0) { \
        snprintf(errbuf, errbuf_sz, "missing SKF symbol %s: %s", #name, last_dl_error()); \
        return -1; \
    } \
} while (0)

static const char *env_or_default(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

static void fill_common(const device_resource_t *device, const translated_call_t *call, response_t *resp) {
    snprintf(resp->selected_device, sizeof(resp->selected_device), "%s", device->device_id);
    snprintf(resp->backend_name, sizeof(resp->backend_name), "%s", call->backend_name);
    snprintf(resp->backend_call, sizeof(resp->backend_call), "%s", call->backend_call_name);
}

static void bytes_to_hex(const BYTE *in, ULONG in_len, char *out, size_t out_sz) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    size_t pos = 0U;
    if (out_sz == 0U) {
        return;
    }
    for (i = 0U; i < (size_t)in_len && pos + 2U < out_sz; ++i) {
        out[pos++] = hex[(in[i] >> 4) & 0x0FU];
        out[pos++] = hex[in[i] & 0x0FU];
    }
    out[pos] = '\0';
}

static ULONG parse_output_len(const char *payload, ULONG fallback) {
    char *end = NULL;
    unsigned long value;
    if (payload == NULL || payload[0] == '\0') {
        return fallback;
    }
    errno = 0;
    value = strtoul(payload, &end, 10);
    if (errno != 0 || end == payload || value == 0UL || value > GM3000_MAX_IO) {
        return fallback;
    }
    return (ULONG)value;
}

static void close_runtime(gm3000_runtime_t *rt) {
    if (rt != NULL && rt->lib != NULL) {
        dlclose(rt->lib);
        rt->lib = NULL;
    }
}

static int open_runtime(gm3000_runtime_t *rt, char *errbuf, size_t errbuf_sz) {
    const char *lib_path = env_or_default("GM3000_SKF_LIB", GM3000_DEFAULT_LIB);
    memset(rt, 0, sizeof(*rt));
    rt->lib = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if (rt->lib == NULL) {
        snprintf(errbuf, errbuf_sz, "dlopen %s failed: %s", lib_path, last_dl_error());
        return -1;
    }
    LOAD_SYMBOL(rt, SKF_EnumDev);
    LOAD_SYMBOL(rt, SKF_ConnectDev);
    LOAD_SYMBOL(rt, SKF_DisConnectDev);
    LOAD_SYMBOL(rt, SKF_GetDevInfo);
    LOAD_SYMBOL(rt, SKF_GenRandom);
    LOAD_SYMBOL(rt, SKF_DigestInit);
    LOAD_SYMBOL(rt, SKF_Digest);
    LOAD_SYMBOL(rt, SKF_CloseHandle);
    return 0;
}

static int first_device_name(gm3000_runtime_t *rt, char *name, size_t name_sz, char *errbuf, size_t errbuf_sz) {
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

static int open_device(gm3000_runtime_t *rt, gm3000_session_t *sess, char *errbuf, size_t errbuf_sz) {
    const char *configured_name = getenv("GM3000_SKF_DEVICE");
    char enum_name[MAX_FIELD_LEN];
    LPSTR dev_name;
    ULONG rv;
    memset(sess, 0, sizeof(*sess));
    if (configured_name != NULL && configured_name[0] != '\0') {
        dev_name = (LPSTR)configured_name;
    } else {
        if (first_device_name(rt, enum_name, sizeof(enum_name), errbuf, errbuf_sz) != 0) {
            return -1;
        }
        dev_name = enum_name;
    }
    rv = rt->SKF_ConnectDev(dev_name, &sess->dev);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_ConnectDev(%s) failed rv=0x%08X", dev_name, rv);
        return -1;
    }
    return 0;
}

static void close_session(gm3000_runtime_t *rt, gm3000_session_t *sess) {
    if (rt != NULL && sess != NULL && sess->dev != NULL) {
        (void)rt->SKF_DisConnectDev(sess->dev);
        sess->dev = NULL;
    }
}

static int open_runtime_device(gm3000_runtime_t *rt, gm3000_session_t *sess, char *errbuf, size_t errbuf_sz) {
    if (open_runtime(rt, errbuf, errbuf_sz) != 0) {
        return -1;
    }
    if (open_device(rt, sess, errbuf, errbuf_sz) != 0) {
        close_runtime(rt);
        return -1;
    }
    return 0;
}

static int gm3000_not_supported(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    (void)device;
    (void)resp;
    snprintf(errbuf, errbuf_sz, "gm3000-skf does not support domain=%s action=%s alg=%s yet", domain_to_string(call->call.domain), action_to_string(call->call.action), call->call.algorithm);
    return -1;
}

static int gm3000_device_manage(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    gm3000_runtime_t rt;
    gm3000_session_t sess;
    int rc = -1;
    fill_common(device, call, resp);
    if (open_runtime_device(&rt, &sess, errbuf, errbuf_sz) != 0) {
        return -1;
    }
    if (call->call.action == ACTION_GENERATE_RANDOM) {
        BYTE buf[GM3000_MAX_IO];
        ULONG out_len = parse_output_len(call->call.payload, 16U);
        ULONG rv = rt.SKF_GenRandom(sess.dev, buf, out_len);
        if (rv == SAR_OK) {
            char hex[GM3000_MAX_IO * 2U + 1U];
            bytes_to_hex(buf, out_len, hex, sizeof(hex));
            snprintf(resp->result, sizeof(resp->result), "gm3000-random(%u,%s)", out_len, hex);
            rc = 0;
        } else {
            snprintf(errbuf, errbuf_sz, "SKF_GenRandom failed rv=0x%08X", rv);
        }
    } else if (call->call.action == ACTION_GET_DEVICE_INFO) {
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
    } else {
        snprintf(errbuf, errbuf_sz, "unsupported gm3000 device action=%s", action_to_string(call->call.action));
    }
    close_session(&rt, &sess);
    close_runtime(&rt);
    return rc;
}

static int gm3000_hash_ops(const device_resource_t *device, const translated_call_t *call, response_t *resp, char *errbuf, size_t errbuf_sz) {
    gm3000_runtime_t rt;
    gm3000_session_t sess;
    HANDLE hash = NULL;
    BYTE digest[64];
    ULONG digest_len = sizeof(digest);
    ULONG rv;
    int rc = -1;
    fill_common(device, call, resp);
    if (call->call.action != ACTION_HASH || strcmp(call->call.algorithm, "sm3") != 0) {
        return gm3000_not_supported(device, call, resp, errbuf, errbuf_sz);
    }
    if (open_runtime_device(&rt, &sess, errbuf, errbuf_sz) != 0) {
        return -1;
    }
    rv = rt.SKF_DigestInit(sess.dev, SGD_SM3, NULL, NULL, 0, &hash);
    if (rv != SAR_OK) {
        snprintf(errbuf, errbuf_sz, "SKF_DigestInit(SM3) failed rv=0x%08X", rv);
    } else {
        rv = rt.SKF_Digest(hash, (BYTE *)call->call.payload, (ULONG)strlen(call->call.payload), digest, &digest_len);
        (void)rt.SKF_CloseHandle(hash);
        if (rv == SAR_OK) {
            char hex[sizeof(digest) * 2U + 1U];
            bytes_to_hex(digest, digest_len, hex, sizeof(hex));
            snprintf(resp->result, sizeof(resp->result), "gm3000-sm3(%s)", hex);
            rc = 0;
        } else {
            snprintf(errbuf, errbuf_sz, "SKF_Digest failed rv=0x%08X", rv);
        }
    }
    close_session(&rt, &sess);
    close_runtime(&rt);
    return rc;
}

driver_ops_t skf_driver_ops(void) {
    driver_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.device_manage = gm3000_device_manage;
    ops.key_manage = gm3000_not_supported;
    ops.asym_crypto = gm3000_not_supported;
    ops.sym_crypto = gm3000_not_supported;
    ops.hash_ops = gm3000_hash_ops;
    ops.file_ops = gm3000_not_supported;
    ops.pqc_ops = gm3000_not_supported;
    return ops;
}
