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
    snprintf(errbuf, errbuf_sz, "pqc adapter does not support domain=%s action=%s alg=%s",
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

static int pqc_device_manage(const device_resource_t *device,
                             const translated_call_t *call,
                             response_t *resp,
                             char *errbuf,
                             size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    if (call->call.action == ACTION_GET_DEVICE_INFO) {
        snprintf(resp->result, sizeof(resp->result), "pqc-device-info(%s)", device->device_id);
        return 0;
    }
    if (call->call.action == ACTION_GENERATE_RANDOM) {
        snprintf(resp->result, sizeof(resp->result), "pqc-random(%s)", call->call.payload[0] == '\0' ? "16" : call->call.payload);
        return 0;
    }
    return not_supported(device, call, resp, errbuf, errbuf_sz);
}

static int pqc_key_manage(const device_resource_t *device,
                          const translated_call_t *call,
                          response_t *resp,
                          char *errbuf,
                          size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_GET_PRIVATE_KEY_ACCESS:
            snprintf(resp->result, sizeof(resp->result), "pqc-key-access-ok(%s)", call->call.key_ref);
            return 0;
        case ACTION_RELEASE_PRIVATE_KEY_ACCESS:
            snprintf(resp->result, sizeof(resp->result), "pqc-key-access-released(%s)", call->call.key_ref);
            return 0;
        case ACTION_GENERATE_KEY_PAIR:
            snprintf(resp->result, sizeof(resp->result), "pqc-keypair(%s,%s)", call->call.algorithm, call->call.key_ref);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

static int pqc_hash(const device_resource_t *device,
                    const translated_call_t *call,
                    response_t *resp,
                    char *errbuf,
                    size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    if (call->call.action == ACTION_HASH) {
        snprintf(resp->result, sizeof(resp->result), "pqc-hash(%s,%s)", call->call.algorithm, call->call.payload);
        return 0;
    }
    return not_supported(device, call, resp, errbuf, errbuf_sz);
}

static int pqc_file(const device_resource_t *device,
                    const translated_call_t *call,
                    response_t *resp,
                    char *errbuf,
                    size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_CREATE_FILE:
            snprintf(resp->result, sizeof(resp->result), "pqc-create-file(%s)", call->call.key_ref);
            return 0;
        case ACTION_READ_FILE:
            snprintf(resp->result, sizeof(resp->result), "pqc-read-file(%s)", call->call.key_ref);
            return 0;
        case ACTION_WRITE_FILE:
            snprintf(resp->result, sizeof(resp->result), "pqc-write-file(%s)", call->call.key_ref);
            return 0;
        case ACTION_DELETE_FILE:
            snprintf(resp->result, sizeof(resp->result), "pqc-delete-file(%s)", call->call.key_ref);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

static int pqc_ops_impl(const device_resource_t *device,
                        const translated_call_t *call,
                        response_t *resp,
                        char *errbuf,
                        size_t errbuf_sz) {
    (void)errbuf;
    (void)errbuf_sz;
    fill_common(device, call, resp);
    switch (call->call.action) {
        case ACTION_SIGN:
            snprintf(resp->result, sizeof(resp->result), "pqc-signature(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_VERIFY:
            snprintf(resp->result, sizeof(resp->result), "pqc-verify-ok(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_KEM_ENCAP:
            snprintf(resp->result, sizeof(resp->result), "pqc-kem-ct(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        case ACTION_KEM_DECAP:
            snprintf(resp->result, sizeof(resp->result), "pqc-kem-ss(%s,%s)", call->call.algorithm, call->call.payload);
            return 0;
        default:
            return not_supported(device, call, resp, errbuf, errbuf_sz);
    }
}

driver_ops_t pqc_driver_ops(void) {
    driver_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.device_manage = pqc_device_manage;
    ops.key_manage = pqc_key_manage;
    ops.asym_crypto = not_supported;
    ops.sym_crypto = not_supported;
    ops.hash_ops = pqc_hash;
    ops.file_ops = pqc_file;
    ops.pqc_ops = pqc_ops_impl;
    return ops;
}
