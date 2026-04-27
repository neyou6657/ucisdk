#include "driver.h"
#include "protocol.h"

#include <stdio.h>

int driver_dispatch(const driver_ops_t *ops,
                    api_domain_t domain,
                    const device_resource_t *device,
                    const translated_call_t *call,
                    response_t *resp,
                    char *errbuf,
                    size_t errbuf_sz) {
    adapter_handler_fn fn = NULL;
    switch (domain) {
        case DOMAIN_DEVICE: fn = ops->device_manage; break;
        case DOMAIN_KEY: fn = ops->key_manage; break;
        case DOMAIN_ASYM: fn = ops->asym_crypto; break;
        case DOMAIN_SYM: fn = ops->sym_crypto; break;
        case DOMAIN_HASH: fn = ops->hash_ops; break;
        case DOMAIN_FILE: fn = ops->file_ops; break;
        case DOMAIN_PQC: fn = ops->pqc_ops; break;
        default:
            snprintf(errbuf, errbuf_sz, "unsupported dispatch domain=%s", domain_to_string(domain));
            return -1;
    }
    if (fn == NULL) {
        snprintf(errbuf, errbuf_sz, "adapter missing handler for domain=%s", domain_to_string(domain));
        return -1;
    }
    return fn(device, call, resp, errbuf, errbuf_sz);
}
