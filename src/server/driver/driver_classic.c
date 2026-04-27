#include "driver.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

static int not_supported(const device_resource_t *device,
                         const translated_call_t *call,
                         response_t *resp,
                         char *errbuf,
                         size_t errbuf_sz) {
    (void)device;
    (void)resp;
    snprintf(errbuf, errbuf_sz, "classic adapter does not support domain=%s action=%s alg=%s",
             domain_to_string(call->call.domain),
             action_to_string(call->call.action),
             call->call.algorithm);
    return -1;
}

static void fill_common(const device_resource_t *device,
                        const translated_call_t *call,
                        response_t *resp) {
    snprintf(resp->selected_device, sizeof(resp->selected_device), "%s", device->device_id);
    snprintf(resp->backend_name, sizeof(resp->backend_name), "%s", call->backend_name);
    snprintf(resp->backend_call, sizeof(resp->backend_call), "%s", call->backend_call_name);
}

static int classic_device_manage(const device_resource_t *device,
                                 const translated_call_t *call,
                                 response_t *resp,
                                 char *errbuf,
                                 size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    if (call->call.action == ACTION_GET_DEVICE_INFO) {
        snprintf(resp->result, sizeof(resp->result), "classic-device-info(%s)", device->device_id);
        return 0;
    }
    if (call->call.action == ACTION_GENERATE_RANDOM) {
        snprintf(resp->result, sizeof(resp->result), "classic-random(%s)", call->call.payload[0] == '\0' ? "16" : call->call.payload);
        return 0;
    }
    return not_supported(device, call, resp, errbuf, errbuf_sz);
}

static int classic_key_manage(const device_resource_t *device,
                              const translated_call_t *call,
                              response_t *resp,
                              char *errbuf,
                              size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_GET_PRIVATE_KEY_ACCESS:
            snprintf(resp->result, sizeof(resp->result), "classic-key-access-ok(%s)", call->call.key_ref);
            return 0;
        case ACTION_RELEASE_PRIVATE_KEY_ACCESS:
            snprintf(resp->result, sizeof(resp->result), "classic-key-access-released(%s)", call->call.key_ref);
            return 0;
        case ACTION_GENERATE_KEY_PAIR:
            snprintf(resp->result, sizeof(resp->result), "classic-keypair(%s,%s)", call->call.algorithm, call->call.key_ref);
            return 0;
        case ACTION_EXPORT_PUBLIC_KEY:
            snprintf(resp->result, sizeof(resp->result), "classic-export-pub(%s,%s)", call->call.algorithm, call->call.key_ref);
            return 0;
        case ACTION_IMPORT_KEY:
            snprintf(resp->result, sizeof(resp->result), "classic-import-key(%s)", call->call.key_ref);
            return 0;
        case ACTION_DESTROY_KEY:
            snprintf(resp->result, sizeof(resp->result), "classic-destroy-key(%s)", call->call.key_ref);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

static int classic_asym(const device_resource_t *device,
                        const translated_call_t *call,
                        response_t *resp,
                        char *errbuf,
                        size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_SIGN:
            snprintf(resp->result, sizeof(resp->result), "classic-signature(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_VERIFY:
            snprintf(resp->result, sizeof(resp->result), "classic-verify-ok(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_ENCRYPT:
            snprintf(resp->result, sizeof(resp->result), "classic-cipher(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_DECRYPT:
            snprintf(resp->result, sizeof(resp->result), "classic-plain(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

static int classic_sym(const device_resource_t *device,
                       const translated_call_t *call,
                       response_t *resp,
                       char *errbuf,
                       size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_ENCRYPT:
            snprintf(resp->result, sizeof(resp->result), "classic-sym-enc(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_DECRYPT:
            snprintf(resp->result, sizeof(resp->result), "classic-sym-dec(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_MAC:
            snprintf(resp->result, sizeof(resp->result), "classic-mac(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

static int classic_hash(const device_resource_t *device,
                        const translated_call_t *call,
                        response_t *resp,
                        char *errbuf,
                        size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    if (call->call.action == ACTION_HASH) {
        snprintf(resp->result, sizeof(resp->result), "classic-hash(%s,%s)", call->call.algorithm, call->call.payload);
        return 0;
    }
    return not_supported(device, call, resp, errbuf, errbuf_sz);
}

static int classic_file(const device_resource_t *device,
                        const translated_call_t *call,
                        response_t *resp,
                        char *errbuf,
                        size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_CREATE_FILE:
            snprintf(resp->result, sizeof(resp->result), "classic-create-file(%s)", call->call.key_ref);
            return 0;
        case ACTION_READ_FILE:
            snprintf(resp->result, sizeof(resp->result), "classic-read-file(%s)", call->call.key_ref);
            return 0;
        case ACTION_WRITE_FILE:
            snprintf(resp->result, sizeof(resp->result), "classic-write-file(%s)", call->call.key_ref);
            return 0;
        case ACTION_DELETE_FILE:
            snprintf(resp->result, sizeof(resp->result), "classic-delete-file(%s)", call->call.key_ref);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

driver_ops_t classic_driver_ops(void) {
    driver_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.device_manage = classic_device_manage;
    ops.key_manage = classic_key_manage;
    ops.asym_crypto = classic_asym;
    ops.sym_crypto = classic_sym;
    ops.hash_ops = classic_hash;
    ops.file_ops = classic_file;
    ops.pqc_ops = not_supported;
    return ops;
}
