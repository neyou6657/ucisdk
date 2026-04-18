#include "protocol.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void copy_lower_trim(const char *in, char *out, size_t out_sz) {
    size_t i = 0;
    if (out_sz == 0) {
        return;
    }
    while (*in != '\0' && isspace((unsigned char)*in)) {
        in++;
    }
    while (*in != '\0' && i + 1 < out_sz) {
        if (!isspace((unsigned char)*in)) {
            out[i++] = (char)tolower((unsigned char)*in);
        }
        in++;
    }
    out[i] = '\0';
}

const char *domain_to_string(api_domain_t domain) {
    switch (domain) {
        case DOMAIN_AUTH: return "auth";
        case DOMAIN_DEVICE: return "device";
        case DOMAIN_KEY: return "key";
        case DOMAIN_ASYM: return "asym";
        case DOMAIN_SYM: return "sym";
        case DOMAIN_HASH: return "hash";
        case DOMAIN_FILE: return "file";
        case DOMAIN_PQC: return "pqc";
        default: return "unknown";
    }
}

const char *action_to_string(api_action_t action) {
    switch (action) {
        case ACTION_CHECK_PIN: return "check_pin";
        case ACTION_GET_DEVICE_INFO: return "get_device_info";
        case ACTION_GENERATE_RANDOM: return "generate_random";
        case ACTION_GET_PRIVATE_KEY_ACCESS: return "get_private_key_access";
        case ACTION_RELEASE_PRIVATE_KEY_ACCESS: return "release_private_key_access";
        case ACTION_GENERATE_KEY_PAIR: return "generate_key_pair";
        case ACTION_EXPORT_PUBLIC_KEY: return "export_public_key";
        case ACTION_IMPORT_KEY: return "import_key";
        case ACTION_DESTROY_KEY: return "destroy_key";
        case ACTION_SIGN: return "sign";
        case ACTION_VERIFY: return "verify";
        case ACTION_ENCRYPT: return "encrypt";
        case ACTION_DECRYPT: return "decrypt";
        case ACTION_MAC: return "mac";
        case ACTION_HASH: return "hash";
        case ACTION_CREATE_FILE: return "create_file";
        case ACTION_READ_FILE: return "read_file";
        case ACTION_WRITE_FILE: return "write_file";
        case ACTION_DELETE_FILE: return "delete_file";
        case ACTION_KEM_ENCAP: return "kem_encap";
        case ACTION_KEM_DECAP: return "kem_decap";
        default: return "unknown";
    }
}

const char *device_type_to_string(device_type_t type) {
    switch (type) {
        case DEV_CLASSIC: return "classic";
        case DEV_PQC: return "pqc";
        default: return "unknown";
    }
}

const char *preference_to_string(preference_t pref) {
    switch (pref) {
        case PREF_SECURE: return "secure";
        case PREF_EFFICIENT: return "efficient";
        case PREF_CLASSIC_FIRST: return "classic_first";
        case PREF_PQC_FIRST: return "pqc_first";
        case PREF_BALANCED:
        default:
            return "balanced";
    }
}

api_domain_t parse_domain(const char *s) {
    char norm[MAX_FIELD_LEN];
    if (s == NULL) {
        return DOMAIN_UNKNOWN;
    }
    copy_lower_trim(s, norm, sizeof(norm));
    if (strcmp(norm, "auth") == 0) return DOMAIN_AUTH;
    if (strcmp(norm, "device") == 0) return DOMAIN_DEVICE;
    if (strcmp(norm, "key") == 0) return DOMAIN_KEY;
    if (strcmp(norm, "asym") == 0) return DOMAIN_ASYM;
    if (strcmp(norm, "sym") == 0) return DOMAIN_SYM;
    if (strcmp(norm, "hash") == 0) return DOMAIN_HASH;
    if (strcmp(norm, "file") == 0) return DOMAIN_FILE;
    if (strcmp(norm, "pqc") == 0) return DOMAIN_PQC;
    return DOMAIN_UNKNOWN;
}

api_action_t parse_action(const char *s) {
    char norm[MAX_FIELD_LEN];
    if (s == NULL) {
        return ACTION_UNKNOWN;
    }
    copy_lower_trim(s, norm, sizeof(norm));
    if (strcmp(norm, "check_pin") == 0) return ACTION_CHECK_PIN;
    if (strcmp(norm, "get_device_info") == 0) return ACTION_GET_DEVICE_INFO;
    if (strcmp(norm, "generate_random") == 0) return ACTION_GENERATE_RANDOM;
    if (strcmp(norm, "get_private_key_access") == 0) return ACTION_GET_PRIVATE_KEY_ACCESS;
    if (strcmp(norm, "release_private_key_access") == 0) return ACTION_RELEASE_PRIVATE_KEY_ACCESS;
    if (strcmp(norm, "generate_key_pair") == 0) return ACTION_GENERATE_KEY_PAIR;
    if (strcmp(norm, "export_public_key") == 0) return ACTION_EXPORT_PUBLIC_KEY;
    if (strcmp(norm, "import_key") == 0) return ACTION_IMPORT_KEY;
    if (strcmp(norm, "destroy_key") == 0) return ACTION_DESTROY_KEY;
    if (strcmp(norm, "sign") == 0) return ACTION_SIGN;
    if (strcmp(norm, "verify") == 0) return ACTION_VERIFY;
    if (strcmp(norm, "encrypt") == 0) return ACTION_ENCRYPT;
    if (strcmp(norm, "decrypt") == 0) return ACTION_DECRYPT;
    if (strcmp(norm, "mac") == 0) return ACTION_MAC;
    if (strcmp(norm, "hash") == 0) return ACTION_HASH;
    if (strcmp(norm, "create_file") == 0) return ACTION_CREATE_FILE;
    if (strcmp(norm, "read_file") == 0) return ACTION_READ_FILE;
    if (strcmp(norm, "write_file") == 0) return ACTION_WRITE_FILE;
    if (strcmp(norm, "delete_file") == 0) return ACTION_DELETE_FILE;
    if (strcmp(norm, "kem_encap") == 0) return ACTION_KEM_ENCAP;
    if (strcmp(norm, "kem_decap") == 0) return ACTION_KEM_DECAP;
    return ACTION_UNKNOWN;
}

device_type_t parse_device_type(const char *s) {
    char norm[MAX_FIELD_LEN];
    if (s == NULL) {
        return DEV_UNKNOWN;
    }
    copy_lower_trim(s, norm, sizeof(norm));
    if (strcmp(norm, "classic") == 0) return DEV_CLASSIC;
    if (strcmp(norm, "pqc") == 0) return DEV_PQC;
    if (strcmp(norm, "auto") == 0) return DEV_UNKNOWN;
    return DEV_UNKNOWN;
}

preference_t parse_preference(const char *s) {
    char norm[MAX_FIELD_LEN];
    if (s == NULL || s[0] == '\0') {
        return PREF_BALANCED;
    }
    copy_lower_trim(s, norm, sizeof(norm));
    if (strcmp(norm, "secure") == 0 || strcmp(norm, "safest") == 0) return PREF_SECURE;
    if (strcmp(norm, "efficient") == 0 || strcmp(norm, "fast") == 0 || strcmp(norm, "highest_efficiency") == 0) return PREF_EFFICIENT;
    if (strcmp(norm, "classic_first") == 0) return PREF_CLASSIC_FIRST;
    if (strcmp(norm, "pqc_first") == 0) return PREF_PQC_FIRST;
    return PREF_BALANCED;
}

int normalize_algorithm_name(const char *in, char *out, size_t out_sz) {
    if (out == NULL || out_sz == 0) {
        return -1;
    }
    if (in == NULL || in[0] == '\0') {
        snprintf(out, out_sz, "%s", "auto");
        return 0;
    }
    copy_lower_trim(in, out, out_sz);
    if (strcmp(out, "auto") == 0 || strcmp(out, "none") == 0) {
        snprintf(out, out_sz, "%s", "auto");
    } else if (strcmp(out, "kyber") == 0 || strcmp(out, "kyber-768") == 0) {
        snprintf(out, out_sz, "%s", "kyber768");
    } else if (strcmp(out, "ml-kem-768") == 0 || strcmp(out, "mlkem") == 0) {
        snprintf(out, out_sz, "%s", "mlkem768");
    } else if (strcmp(out, "dilithium") == 0 || strcmp(out, "dilithium-3") == 0) {
        snprintf(out, out_sz, "%s", "dilithium3");
    }
    return out[0] == '\0' ? -1 : 0;
}

static int extract_json_string(const char *json, const char *key, char *out, size_t out_sz) {
    char needle[128];
    const char *p;
    size_t i = 0;

    snprintf(needle, sizeof(needle), "\"%s\"", key);
    p = strstr(json, needle);
    if (p == NULL) {
        return -1;
    }
    p = strchr(p + strlen(needle), ':');
    if (p == NULL) {
        return -1;
    }
    p++;
    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }
    if (*p != '"') {
        return -1;
    }
    p++;
    while (*p != '\0' && *p != '"') {
        if (i + 1 >= out_sz) {
            return -2;
        }
        out[i++] = *p++;
    }
    if (*p != '"') {
        return -1;
    }
    out[i] = '\0';
    return 0;
}

static void default_algorithm_for(api_domain_t domain, api_action_t action, char *algorithm, size_t sz) {
    (void)domain;
    if (action == ACTION_HASH) {
        snprintf(algorithm, sz, "%s", "sm3");
    } else {
        snprintf(algorithm, sz, "%s", "auto");
    }
}

int parse_request_json(const char *json_line, request_t *out, char *errbuf, size_t errbuf_sz) {
    char domain[MAX_FIELD_LEN] = {0};
    char action[MAX_FIELD_LEN] = {0};
    char algorithm[MAX_FIELD_LEN] = {0};
    char preference[MAX_FIELD_LEN] = {0};

    memset(out, 0, sizeof(*out));
    out->preference = PREF_BALANCED;

    if (extract_json_string(json_line, "request_id", out->request_id, sizeof(out->request_id)) != 0) {
        snprintf(errbuf, errbuf_sz, "missing or invalid request_id");
        return -1;
    }
    if (extract_json_string(json_line, "domain", domain, sizeof(domain)) != 0) {
        snprintf(errbuf, errbuf_sz, "missing or invalid domain");
        return -1;
    }
    if (extract_json_string(json_line, "action", action, sizeof(action)) != 0) {
        snprintf(errbuf, errbuf_sz, "missing or invalid action");
        return -1;
    }
    if (extract_json_string(json_line, "algorithm", algorithm, sizeof(algorithm)) != 0) {
        default_algorithm_for(parse_domain(domain), parse_action(action), algorithm, sizeof(algorithm));
    }
    if (extract_json_string(json_line, "key_ref", out->key_ref, sizeof(out->key_ref)) != 0) {
        out->key_ref[0] = '\0';
    }
    if (extract_json_string(json_line, "payload", out->payload, sizeof(out->payload)) != 0) {
        out->payload[0] = '\0';
    }
    if (extract_json_string(json_line, "aux_payload", out->aux_payload, sizeof(out->aux_payload)) != 0) {
        out->aux_payload[0] = '\0';
    }
    if (extract_json_string(json_line, "device_hint", out->device_hint, sizeof(out->device_hint)) != 0) {
        out->device_hint[0] = '\0';
    }
    if (extract_json_string(json_line, "user_pin", out->user_pin, sizeof(out->user_pin)) != 0) {
        out->user_pin[0] = '\0';
    }
    if (extract_json_string(json_line, "preference", preference, sizeof(preference)) == 0) {
        out->preference = parse_preference(preference);
    }
    if (extract_json_string(json_line, "sequence", out->sequence, sizeof(out->sequence)) != 0) {
        out->sequence[0] = '\0';
    }

    out->domain = parse_domain(domain);
    if (out->domain == DOMAIN_UNKNOWN) {
        snprintf(errbuf, errbuf_sz, "unsupported domain: %s", domain);
        return -1;
    }
    out->action = parse_action(action);
    if (out->action == ACTION_UNKNOWN) {
        snprintf(errbuf, errbuf_sz, "unsupported action: %s", action);
        return -1;
    }
    if (normalize_algorithm_name(algorithm, out->algorithm, sizeof(out->algorithm)) != 0) {
        snprintf(errbuf, errbuf_sz, "unsupported algorithm: %s", algorithm);
        return -1;
    }
    return 0;
}

int response_to_json(const response_t *resp, char *buf, size_t buf_sz) {
    return snprintf(buf,
                    buf_sz,
                    "{\"request_id\":\"%s\",\"status\":%d,\"selected_device\":\"%s\",\"backend_name\":\"%s\",\"backend_call\":\"%s\",\"trace\":\"%s\",\"result\":\"%s\"}",
                    resp->request_id,
                    (int)resp->status,
                    resp->selected_device,
                    resp->backend_name,
                    resp->backend_call,
                    resp->trace,
                    resp->result);
}
