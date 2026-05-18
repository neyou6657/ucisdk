#include "scheduler.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    api_domain_t domain;
    api_action_t action;
    device_type_t preferred_type;
    char algorithm[MAX_FIELD_LEN];
} sequence_step_t;

void scheduler_init(scheduler_t *scheduler,
                    resource_registry_t *registry,
                    const gateway_settings_t *gateway_settings) {
    scheduler->registry = registry;
    scheduler->gateway_settings = gateway_settings;
}

static void build_error_response(const request_t *req, response_t *resp, status_code_t status, const char *msg) {
    memset(resp, 0, sizeof(*resp));
    snprintf(resp->request_id, sizeof(resp->request_id), "%s", req->request_id);
    resp->status = status;
    snprintf(resp->result, sizeof(resp->result), "%s", msg);
}

static void append_with_sep(char *dst, size_t dst_sz, const char *value, const char *sep) {
    if (value == NULL || value[0] == '\0') {
        return;
    }
    if (dst[0] != '\0') {
        strncat(dst, sep, dst_sz - strlen(dst) - 1U);
    }
    strncat(dst, value, dst_sz - strlen(dst) - 1U);
}

static int validate_gateway_pin(const scheduler_t *scheduler, const request_t *req, response_t *resp) {
    if (scheduler->gateway_settings == NULL || scheduler->gateway_settings->gateway_pin[0] == '\0') {
        return 0;
    }
    if (req->action == ACTION_CHECK_PIN && req->domain == DOMAIN_AUTH) {
        if (strcmp(req->user_pin, scheduler->gateway_settings->gateway_pin) == 0) {
            memset(resp, 0, sizeof(*resp));
            snprintf(resp->request_id, sizeof(resp->request_id), "%s", req->request_id);
            resp->status = STATUS_OK;
            snprintf(resp->backend_name, sizeof(resp->backend_name), "%s", "gateway-auth");
            snprintf(resp->backend_call, sizeof(resp->backend_call), "%s", "check_pin");
            snprintf(resp->result, sizeof(resp->result), "%s", "pin_ok");
            return 1;
        }
        build_error_response(req, resp, STATUS_UNAUTHORIZED, "invalid gateway pin");
        return -1;
    }
    if (strcmp(req->user_pin, scheduler->gateway_settings->gateway_pin) != 0) {
        build_error_response(req, resp, STATUS_UNAUTHORIZED, "gateway pin check failed");
        return -1;
    }
    return 0;
}

static void build_order(preference_t pref,
                        device_type_t explicit_type,
                        device_type_t *order,
                        size_t *order_len) {
    *order_len = 0;
    if (explicit_type != DEV_UNKNOWN) {
        order[(*order_len)++] = explicit_type;
        return;
    }
    switch (pref) {
        case PREF_PQC_FIRST:
        case PREF_SECURE:
            order[(*order_len)++] = DEV_PQC;
            order[(*order_len)++] = DEV_CLASSIC;
            break;
        case PREF_CLASSIC_FIRST:
        case PREF_EFFICIENT:
        case PREF_BALANCED:
        default:
            order[(*order_len)++] = DEV_CLASSIC;
            order[(*order_len)++] = DEV_PQC;
            break;
    }
}


static int key_ref_get_token(const char *key_ref, const char *name, char *out, size_t out_sz) {
    char tmp[MAX_FIELD_LEN];
    char *save = NULL;
    char *token;
    size_t name_len;

    if (out == NULL || out_sz == 0U) return -1;
    out[0] = '\0';
    if (key_ref == NULL || key_ref[0] == '\0' || name == NULL || name[0] == '\0') return -1;

    snprintf(tmp, sizeof(tmp), "%s", key_ref);
    name_len = strlen(name);
    token = strtok_r(tmp, ";", &save);
    while (token != NULL) {
        if (strncmp(token, name, name_len) == 0 && token[name_len] == '=') {
            snprintf(out, out_sz, "%s", token + name_len + 1U);
            return out[0] == '\0' ? -1 : 0;
        }
        token = strtok_r(NULL, ";", &save);
    }
    return -1;
}

static int key_ref_is_internal_index(const char *key_ref) {
    char source[MAX_FIELD_LEN];
    if (key_ref_get_token(key_ref, "source", source, sizeof(source)) != 0) return 0;
    return strcmp(source, "1") == 0 || strcmp(source, "internal_index") == 0;
}


static unsigned int key_ref_source_value(const char *key_ref) {
    char source[MAX_FIELD_LEN];
    if (key_ref_get_token(key_ref, "source", source, sizeof(source)) != 0) return 0U;
    if (strcmp(source, "internal_index") == 0) return 1U;
    if (strcmp(source, "session_handle") == 0) return 2U;
    if (strcmp(source, "external_key") == 0) return 3U;
    if (strcmp(source, "managed_key") == 0) return 4U;
    if (strcmp(source, "1") == 0) return 1U;
    if (strcmp(source, "2") == 0) return 2U;
    if (strcmp(source, "3") == 0) return 3U;
    if (strcmp(source, "4") == 0) return 4U;
    return 0U;
}

static int resolve_device_hint_from_key_ref(const request_t *req,
                                            const char *key_ref,
                                            char *effective_hint,
                                            size_t effective_hint_sz,
                                            char *errbuf,
                                            size_t errbuf_sz) {
    char key_device_id[MAX_FIELD_LEN];

    effective_hint[0] = '\0';
    if (req->device_hint[0] != '\0') {
        snprintf(effective_hint, effective_hint_sz, "%s", req->device_hint);
    }
    if (!key_ref_is_internal_index(key_ref)) {
        return 0;
    }
    if (key_ref_get_token(key_ref, "device_id", key_device_id, sizeof(key_device_id)) == 0) {
        if (effective_hint[0] != '\0' && strcmp(effective_hint, key_device_id) != 0) {
            snprintf(errbuf, errbuf_sz, "internal_index key device_id conflicts with device_hint");
            return -1;
        }
        snprintf(effective_hint, effective_hint_sz, "%s", key_device_id);
        return 0;
    }
    if (effective_hint[0] != '\0') {
        return 0;
    }
    snprintf(errbuf, errbuf_sz, "internal_index key requires device_id or device_hint");
    return -1;
}

static int execute_single_step(scheduler_t *scheduler,
                               const request_t *req,
                               api_domain_t domain,
                               api_action_t action,
                               const char *algorithm,
                               const char *payload,
                               const char *aux_payload,
                               const char *key_ref,
                               device_type_t explicit_type,
                               response_t *resp,
                               char *errbuf,
                               size_t errbuf_sz) {
    device_resource_t *device = NULL;
    device_type_t order[2];
    size_t order_len = 0;
    translated_call_t translated;
    driver_ops_t ops;
    char effective_device_hint[MAX_FIELD_LEN];
    const char *device_hint;

    if (resolve_device_hint_from_key_ref(req, key_ref, effective_device_hint, sizeof(effective_device_hint), errbuf, errbuf_sz) != 0) {
        return -1;
    }
    device_hint = (effective_device_hint[0] != '\0') ? effective_device_hint : ((explicit_type == DEV_UNKNOWN) ? req->device_hint : "");

    build_order(req->preference, explicit_type, order, &order_len);
    if (registry_acquire_candidate(scheduler->registry,
                                   domain,
                                   action,
                                   algorithm,
                                   device_hint,
                                   key_ref_source_value(key_ref),
                                   req->preference,
                                   order,
                                   order_len,
                                   &device) != 0) {
        snprintf(errbuf, errbuf_sz, "no available device matches domain=%s action=%s alg=%s",
                 domain_to_string(domain), action_to_string(action), algorithm);
        return -1;
    }

    if (translate_backend_call(domain, action, algorithm, payload, aux_payload, key_ref, device, &translated, errbuf, errbuf_sz) != 0) {
        registry_release(scheduler->registry, device->device_id);
        return -1;
    }

    if (strcmp(device->backend_profile, "gm3000-skf") == 0) {
        ops = skf_driver_ops();
    } else {
        ops = (device->type == DEV_CLASSIC) ? classic_driver_ops() : pqc_driver_ops();
    }
    if (driver_dispatch(&ops, domain, device, &translated, resp, errbuf, errbuf_sz) != 0) {
        registry_release(scheduler->registry, device->device_id);
        return -1;
    }

    registry_release(scheduler->registry, device->device_id);
    return 0;
}

static int parse_sequence(const request_t *req, sequence_step_t *steps, size_t *step_count, char *errbuf, size_t errbuf_sz) {
    char sequence[MAX_PAYLOAD_LEN];
    char *save_outer = NULL;
    char *token;
    *step_count = 0;
    if (req->sequence[0] == '\0') {
        return 0;
    }
    snprintf(sequence, sizeof(sequence), "%s", req->sequence);
    token = strtok_r(sequence, ">", &save_outer);
    while (token != NULL) {
        char step_buf[MAX_FIELD_LEN];
        char *save_inner = NULL;
        char *part;
        sequence_step_t *step;
        if (*step_count >= MAX_SEQUENCE_STEPS) {
            snprintf(errbuf, errbuf_sz, "too many sequence steps");
            return -1;
        }
        snprintf(step_buf, sizeof(step_buf), "%s", token);
        step = &steps[*step_count];
        memset(step, 0, sizeof(*step));
        step->preferred_type = DEV_UNKNOWN;

        part = strtok_r(step_buf, ":", &save_inner);
        if (part == NULL) {
            snprintf(errbuf, errbuf_sz, "invalid sequence token: %s", token);
            return -1;
        }
        step->domain = parse_domain(part);
        part = strtok_r(NULL, ":", &save_inner);
        if (part == NULL) {
            snprintf(errbuf, errbuf_sz, "missing sequence action in %s", token);
            return -1;
        }
        step->action = parse_action(part);
        part = strtok_r(NULL, ":", &save_inner);
        if (part == NULL) {
            snprintf(errbuf, errbuf_sz, "missing sequence type in %s", token);
            return -1;
        }
        step->preferred_type = parse_device_type(part);
        part = strtok_r(NULL, ":", &save_inner);
        if (part == NULL || normalize_algorithm_name(part, step->algorithm, sizeof(step->algorithm)) != 0) {
            snprintf(errbuf, errbuf_sz, "invalid sequence algorithm in %s", token);
            return -1;
        }
        if (step->domain == DOMAIN_UNKNOWN || step->action == ACTION_UNKNOWN || step->preferred_type == DEV_UNKNOWN) {
            snprintf(errbuf, errbuf_sz, "invalid sequence token: %s", token);
            return -1;
        }
        (*step_count)++;
        token = strtok_r(NULL, ">", &save_outer);
    }
    return 0;
}

static int execute_sequence(scheduler_t *scheduler, const request_t *req, response_t *resp) {
    sequence_step_t steps[MAX_SEQUENCE_STEPS];
    size_t step_count = 0;
    size_t i;
    char errbuf[256];
    char current_payload[MAX_RESPONSE_LEN];

    snprintf(current_payload, sizeof(current_payload), "%s", req->payload);
    if (parse_sequence(req, steps, &step_count, errbuf, sizeof(errbuf)) != 0) {
        build_error_response(req, resp, STATUS_BAD_REQUEST, errbuf);
        return -1;
    }
    if (step_count == 0) {
        return 0;
    }

    for (i = 0; i < step_count; ++i) {
        response_t step_resp;
        memset(&step_resp, 0, sizeof(step_resp));
        if (execute_single_step(scheduler,
                                req,
                                steps[i].domain,
                                steps[i].action,
                                steps[i].algorithm,
                                current_payload,
                                req->aux_payload,
                                req->key_ref,
                                steps[i].preferred_type,
                                &step_resp,
                                errbuf,
                                sizeof(errbuf)) != 0) {
            build_error_response(req, resp, STATUS_BACKEND_FAIL, errbuf);
            return -1;
        }
        append_with_sep(resp->selected_device, sizeof(resp->selected_device), step_resp.selected_device, ">");
        append_with_sep(resp->backend_name, sizeof(resp->backend_name), step_resp.backend_name, ">");
        append_with_sep(resp->backend_call, sizeof(resp->backend_call), step_resp.backend_call, ">");
        append_with_sep(resp->trace, sizeof(resp->trace), step_resp.result, " => ");
        snprintf(current_payload, sizeof(current_payload), "%s", step_resp.result);
    }

    snprintf(resp->result, sizeof(resp->result), "%s", current_payload);
    resp->status = STATUS_OK;
    return 0;
}

int scheduler_execute(scheduler_t *scheduler, const request_t *req, response_t *resp) {
    char errbuf[256];
    int pin_check;

    memset(resp, 0, sizeof(*resp));
    snprintf(resp->request_id, sizeof(resp->request_id), "%s", req->request_id);

    pin_check = validate_gateway_pin(scheduler, req, resp);
    if (pin_check != 0) {
        return pin_check > 0 ? 0 : -1;
    }

    if (req->sequence[0] != '\0') {
        return execute_sequence(scheduler, req, resp);
    }

    if (execute_single_step(scheduler,
                            req,
                            req->domain,
                            req->action,
                            req->algorithm,
                            req->payload,
                            req->aux_payload,
                            req->key_ref,
                            DEV_UNKNOWN,
                            resp,
                            errbuf,
                            sizeof(errbuf)) != 0) {
        build_error_response(req, resp, STATUS_NO_RESOURCE, errbuf);
        return -1;
    }

    resp->trace[0] = '\0';
    append_with_sep(resp->trace, sizeof(resp->trace), resp->selected_device, ":");
    append_with_sep(resp->trace, sizeof(resp->trace), resp->backend_call, ":");
    append_with_sep(resp->trace, sizeof(resp->trace), resp->result, ":");
    resp->status = STATUS_OK;
    return 0;
}
