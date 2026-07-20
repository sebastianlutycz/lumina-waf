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

int main(void) {
    int passed = 0;

    passed += check_worker_lifecycle();
    passed += check_one_byte_generated_rule();
    passed += check_metadata_without_uri();

    printf("RC runtime sanity: %d/3 passed\n", passed);
    luminawaf_destroy_worker();
    return passed == 3 ? 0 : 1;
}
