#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

const char *domain_to_string(api_domain_t domain);
const char *action_to_string(api_action_t action);
const char *device_type_to_string(device_type_t type);
const char *preference_to_string(preference_t pref);

api_domain_t parse_domain(const char *s);
api_action_t parse_action(const char *s);
device_type_t parse_device_type(const char *s);
preference_t parse_preference(const char *s);

int normalize_algorithm_name(const char *in, char *out, size_t out_sz);
int parse_request_json(const char *json_line, request_t *out, char *errbuf, size_t errbuf_sz);
int response_to_json(const response_t *resp, char *buf, size_t buf_sz);

#endif
