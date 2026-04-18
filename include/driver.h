#ifndef DRIVER_H
#define DRIVER_H

#include "common.h"
#include "resource.h"
#include "translator.h"

typedef int (*adapter_handler_fn)(const device_resource_t *device,
                                  const translated_call_t *call,
                                  response_t *resp,
                                  char *errbuf,
                                  size_t errbuf_sz);

typedef struct driver_ops {
    adapter_handler_fn device_manage;
    adapter_handler_fn key_manage;
    adapter_handler_fn asym_crypto;
    adapter_handler_fn sym_crypto;
    adapter_handler_fn hash_ops;
    adapter_handler_fn file_ops;
    adapter_handler_fn pqc_ops;
} driver_ops_t;

driver_ops_t classic_driver_ops(void);
driver_ops_t pqc_driver_ops(void);
int driver_dispatch(const driver_ops_t *ops,
                    api_domain_t domain,
                    const device_resource_t *device,
                    const translated_call_t *call,
                    response_t *resp,
                    char *errbuf,
                    size_t errbuf_sz);

#endif
