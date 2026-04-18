#ifndef COMMON_H
#define COMMON_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_ID_LEN 64
#define MAX_FIELD_LEN 256
#define MAX_PAYLOAD_LEN 1024
#define MAX_CAPS 48
#define MAX_DEVICES 32
#define MAX_QUEUE_DEPTH 128
#define MAX_RESPONSE_LEN 2048
#define DEFAULT_WORKERS 4
#define MAX_SEQUENCE_STEPS 4

/*
 * Unified API domains.
 * AUTH is gateway-only; the seven adapter families are DEVICE/KEY/ASYM/SYM/HASH/FILE/PQC.
 */
typedef enum {
    DOMAIN_UNKNOWN = 0,
    DOMAIN_AUTH,
    DOMAIN_DEVICE,
    DOMAIN_KEY,
    DOMAIN_ASYM,
    DOMAIN_SYM,
    DOMAIN_HASH,
    DOMAIN_FILE,
    DOMAIN_PQC
} api_domain_t;

typedef enum {
    ACTION_UNKNOWN = 0,
    ACTION_CHECK_PIN,
    ACTION_GET_DEVICE_INFO,
    ACTION_GENERATE_RANDOM,
    ACTION_GET_PRIVATE_KEY_ACCESS,
    ACTION_RELEASE_PRIVATE_KEY_ACCESS,
    ACTION_GENERATE_KEY_PAIR,
    ACTION_EXPORT_PUBLIC_KEY,
    ACTION_IMPORT_KEY,
    ACTION_DESTROY_KEY,
    ACTION_SIGN,
    ACTION_VERIFY,
    ACTION_ENCRYPT,
    ACTION_DECRYPT,
    ACTION_MAC,
    ACTION_HASH,
    ACTION_CREATE_FILE,
    ACTION_READ_FILE,
    ACTION_WRITE_FILE,
    ACTION_DELETE_FILE,
    ACTION_KEM_ENCAP,
    ACTION_KEM_DECAP
} api_action_t;

typedef enum {
    DEV_UNKNOWN = 0,
    DEV_CLASSIC,
    DEV_PQC
} device_type_t;

typedef enum {
    PREF_BALANCED = 0,
    PREF_SECURE,
    PREF_EFFICIENT,
    PREF_CLASSIC_FIRST,
    PREF_PQC_FIRST
} preference_t;

typedef enum {
    STATUS_OK = 0,
    STATUS_BAD_REQUEST = 400,
    STATUS_UNAUTHORIZED = 401,
    STATUS_NOT_SUPPORTED = 422,
    STATUS_BACKEND_FAIL = 502,
    STATUS_NO_RESOURCE = 503
} status_code_t;

typedef struct {
    char request_id[MAX_ID_LEN];
    api_domain_t domain;
    api_action_t action;
    char algorithm[MAX_FIELD_LEN];
    char key_ref[MAX_FIELD_LEN];
    char payload[MAX_PAYLOAD_LEN];
    char aux_payload[MAX_PAYLOAD_LEN];
    char device_hint[MAX_FIELD_LEN];
    char user_pin[MAX_FIELD_LEN];
    preference_t preference;
    char sequence[MAX_PAYLOAD_LEN];
} request_t;

typedef struct {
    char request_id[MAX_ID_LEN];
    status_code_t status;
    char selected_device[MAX_RESPONSE_LEN];
    char backend_name[MAX_RESPONSE_LEN];
    char backend_call[MAX_RESPONSE_LEN];
    char trace[MAX_RESPONSE_LEN];
    char result[MAX_RESPONSE_LEN];
} response_t;

typedef struct {
    api_domain_t domain;
    api_action_t action;
    char algorithm[MAX_FIELD_LEN];
    char key_ref[MAX_FIELD_LEN];
    char payload[MAX_PAYLOAD_LEN];
    char aux_payload[MAX_PAYLOAD_LEN];
} backend_call_t;

typedef struct {
    char gateway_pin[MAX_FIELD_LEN];
} gateway_settings_t;

#endif
