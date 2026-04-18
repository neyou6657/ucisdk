#ifndef TRANSLATOR_H
#define TRANSLATOR_H

#include "common.h"
#include "resource.h"

typedef struct {
    backend_call_t call;
    char backend_name[MAX_FIELD_LEN];
    char backend_call_name[MAX_FIELD_LEN];
} translated_call_t;

int translate_request_for_device(const request_t *req,
                                 const device_resource_t *device,
                                 translated_call_t *out,
                                 char *errbuf,
                                 size_t errbuf_sz);

int translate_backend_call(api_domain_t domain,
                           api_action_t action,
                           const char *algorithm,
                           const char *payload,
                           const char *aux_payload,
                           const char *key_ref,
                           const device_resource_t *device,
                           translated_call_t *out,
                           char *errbuf,
                           size_t errbuf_sz);

#endif
