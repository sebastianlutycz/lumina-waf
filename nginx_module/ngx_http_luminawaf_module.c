#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>

#include <luminawaf.h>

typedef struct {
    ngx_flag_t  enable;
} ngx_http_luminawaf_loc_conf_t;

static ngx_int_t ngx_http_luminawaf_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_luminawaf_init(ngx_conf_t *cf);
static void *ngx_http_luminawaf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_luminawaf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_luminawaf_init_process(ngx_cycle_t *cycle);
static void ngx_http_luminawaf_exit_process(ngx_cycle_t *cycle);
#ifdef LUMINA_WILD_WASTELAND
static ngx_int_t ngx_http_luminawaf_wild_response(ngx_http_request_t *r);
#endif

static ngx_inline void
ngx_http_luminawaf_bundle_add(LuminaBundle *bundle, const ngx_str_t *value,
                              const ngx_str_t *name,
                              LuminaVarType var_type, uint32_t scope,
                              uint32_t header_mask)
{
    BundleVar *var;

    if (value == NULL || value->data == NULL ||
        (value->len == 0 && name == NULL) || bundle->count >= 16) {
        return;
    }

    var = &bundle->vars[bundle->count++];
    var->ptr = value->data;
    var->len = value->len;
    var->var_type = (uint8_t) var_type;
    var->scope = scope;
    var->header_mask = header_mask;
    switch (var_type) {
        case LUMINA_VAR_ARGS:
            var->collection_mask = LUMINA_COL_ARGS;
            break;
        case LUMINA_VAR_ARGS_NAMES:
            var->collection_mask = LUMINA_COL_ARGS_NAMES;
            break;
        case LUMINA_VAR_COOKIE:
            var->collection_mask = LUMINA_COL_REQUEST_COOKIES;
            break;
        case LUMINA_VAR_COOKIE_NAMES:
            var->collection_mask = LUMINA_COL_REQUEST_COOKIES_NAMES;
            break;
        case LUMINA_VAR_HDR:
            var->collection_mask = LUMINA_COL_REQUEST_HEADERS;
            break;
        case LUMINA_VAR_BODY:
            var->collection_mask = LUMINA_COL_REQUEST_BODY;
            break;
        case LUMINA_VAR_FILES:
            var->collection_mask = LUMINA_COL_FILES;
            break;
        case LUMINA_VAR_FILES_NAMES:
            var->collection_mask = LUMINA_COL_FILES_NAMES;
            break;
        case LUMINA_VAR_REQUEST_FILENAME:
            var->collection_mask = LUMINA_COL_REQUEST_FILENAME;
            break;
        case LUMINA_VAR_REQUEST_BASENAME:
            var->collection_mask = LUMINA_COL_REQUEST_BASENAME;
            break;
        case LUMINA_VAR_XML:
        case LUMINA_VAR_XML_ATTR:
            var->collection_mask = LUMINA_COL_XML;
            break;
        default:
            var->collection_mask = 0;
            break;
    }
    var->name = name != NULL ? name->data : NULL;
    var->name_len = name != NULL ? name->len : 0;
}

static ngx_inline uint32_t
ngx_http_luminawaf_header_mask(const ngx_str_t *key)
{
#define LUMINA_HEADER_MASK(literal, flag)                                         \
    do {                                                                          \
        static u_char name[] = literal;                                           \
        if (key->len == sizeof(name) - 1 &&                                       \
            ngx_strncasecmp(key->data, name, sizeof(name) - 1) == 0) {            \
            return flag;                                                          \
        }                                                                         \
    } while (0)

    LUMINA_HEADER_MASK("Content-Length", LUMINA_HDR_CONTENT_LENGTH);
    LUMINA_HEADER_MASK("Request-Range", LUMINA_HDR_REQUEST_RANGE);
    LUMINA_HEADER_MASK("Connection", LUMINA_HDR_CONNECTION);
    LUMINA_HEADER_MASK("Host", LUMINA_HDR_HOST);
    LUMINA_HEADER_MASK("User-Agent", LUMINA_HDR_USER_AGENT);
    LUMINA_HEADER_MASK("Content-Type", LUMINA_HDR_CONTENT_TYPE);
    LUMINA_HEADER_MASK("Accept-Encoding", LUMINA_HDR_ACCEPT_ENCODING);
    LUMINA_HEADER_MASK("Accept", LUMINA_HDR_ACCEPT);
    LUMINA_HEADER_MASK("Cookie", LUMINA_HDR_COOKIE);
    LUMINA_HEADER_MASK("Referer", LUMINA_HDR_REFERER);
    LUMINA_HEADER_MASK("X-Filename", LUMINA_HDR_X_FILENAME);
    LUMINA_HEADER_MASK("X_Filename", LUMINA_HDR_X_FILENAME);
    LUMINA_HEADER_MASK("X.Filename", LUMINA_HDR_X_FILENAME);
    LUMINA_HEADER_MASK("X-File-Name", LUMINA_HDR_X_FILENAME);
    LUMINA_HEADER_MASK("Range", LUMINA_HDR_RANGE);

#undef LUMINA_HEADER_MASK
    return 0;
}

static ngx_inline void
ngx_http_luminawaf_count_header(LuminaBundle *bundle, const ngx_table_elt_t *header)
{
#define LUMINA_COUNT_HEADER(field, literal)                                      \
    do {                                                                          \
        static u_char name[] = literal;                                           \
        if (header->key.len == sizeof(name) - 1 &&                                \
            ngx_strncasecmp(header->key.data, name, sizeof(name) - 1) == 0) {     \
            if (bundle->field != UINT16_MAX) bundle->field++;                     \
            return;                                                               \
        }                                                                         \
    } while (0)

    LUMINA_COUNT_HEADER(hdr_host_count, "Host");
    LUMINA_COUNT_HEADER(hdr_user_agent_count, "User-Agent");
    LUMINA_COUNT_HEADER(hdr_content_type_count, "Content-Type");
    LUMINA_COUNT_HEADER(hdr_request_range_count, "Request-Range");
    LUMINA_COUNT_HEADER(hdr_transfer_encoding_count, "Transfer-Encoding");

#undef LUMINA_COUNT_HEADER
}

static ngx_inline void
ngx_http_luminawaf_set_reqbody_processor(LuminaBundle *bundle,
                                         const ngx_str_t *content_type)
{
    static u_char urlencoded_type[] = "application/x-www-form-urlencoded";
    static u_char json_type[] = "application/json";
    static u_char application_xml_type[] = "application/xml";
    static u_char text_xml_type[] = "text/xml";
    static u_char urlencoded_processor[] = "URLENCODED";
    static u_char json_processor[] = "JSON";
    static u_char xml_processor[] = "XML";
    size_t media_len = 0;

    if (content_type == NULL || content_type->data == NULL) return;
    while (media_len < content_type->len &&
           content_type->data[media_len] != ';' &&
           content_type->data[media_len] != ' ' &&
           content_type->data[media_len] != '\t') {
        media_len++;
    }

    if (media_len == sizeof(urlencoded_type) - 1 &&
        ngx_strncasecmp(content_type->data, urlencoded_type, media_len) == 0) {
        bundle->reqbody_processor = urlencoded_processor;
        bundle->reqbody_processor_len = sizeof(urlencoded_processor) - 1;
    } else if ((media_len == sizeof(json_type) - 1 &&
                ngx_strncasecmp(content_type->data, json_type, media_len) == 0) ||
               (media_len >= 5 &&
                ngx_strncasecmp(content_type->data + media_len - 5,
                                (u_char *) "+json", 5) == 0)) {
        bundle->reqbody_processor = json_processor;
        bundle->reqbody_processor_len = sizeof(json_processor) - 1;
    } else if ((media_len == sizeof(application_xml_type) - 1 &&
                ngx_strncasecmp(content_type->data, application_xml_type, media_len) == 0) ||
               (media_len == sizeof(text_xml_type) - 1 &&
                ngx_strncasecmp(content_type->data, text_xml_type, media_len) == 0) ||
               (media_len >= 4 &&
                ngx_strncasecmp(content_type->data + media_len - 4,
                                (u_char *) "+xml", 4) == 0)) {
        bundle->reqbody_processor = xml_processor;
        bundle->reqbody_processor_len = sizeof(xml_processor) - 1;
    }
}

static ngx_command_t ngx_http_luminawaf_commands[] = {
    { ngx_string("lumina_waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_luminawaf_loc_conf_t, enable),
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_luminawaf_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_luminawaf_init,               /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_luminawaf_create_loc_conf,    /* create location configuration */
    ngx_http_luminawaf_merge_loc_conf      /* merge location configuration */
};

ngx_module_t ngx_http_luminawaf_module = {
    NGX_MODULE_V1,
    &ngx_http_luminawaf_module_ctx,        /* module context */
    ngx_http_luminawaf_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_luminawaf_init_process,       /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_luminawaf_exit_process,       /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_luminawaf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_luminawaf_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_luminawaf_loc_conf_t));
    if (conf == NULL) return NULL;
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_luminawaf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_luminawaf_loc_conf_t *prev = parent;
    ngx_http_luminawaf_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_luminawaf_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_luminawaf_handler;
    return NGX_OK;
}

static ngx_int_t ngx_http_luminawaf_init_process(ngx_cycle_t *cycle) {
    // Initialize Lumina WAF with 4096 concurrent connections expected (allocates arenas)
    if (luminawaf_init_worker(4096) != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Failed to initialize Lumina WAF worker arenas.");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void ngx_http_luminawaf_exit_process(ngx_cycle_t *cycle) {
    luminawaf_destroy_worker();
}

static void ngx_http_luminawaf_add_origin_header(ngx_http_request_t *r) {
    if (ngx_strcmp((u_char *)luminawaf_license_mode(), (u_char *)"AGPLv3") != 0) {
        return;
    }

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return;

    h->hash = 1;
    ngx_str_set(&h->key, "X-LuminaWAF-Id");
    h->value.data = ngx_pnalloc(r->pool, 64);
    if (h->value.data == NULL) {
        h->hash = 0;
        return;
    }
    h->value.len = ngx_sprintf(h->value.data, "%s (%s)",
                               luminawaf_build_fingerprint(),
                               luminawaf_license_mode()) - h->value.data;
}

#ifdef LUMINA_WILD_WASTELAND
/*
 * You have discovered an unusual implementation detail.
 * The normal response path remains unchanged when this macro is absent.
 * No retaliation. No reflection. No resource exhaustion.
 */
static ngx_int_t ngx_http_luminawaf_wild_response(ngx_http_request_t *r) {
    static u_char body[] =
        "Wild Wasteland\n"
        "\n"
        "I'm a teapot.\n"
        "The request failed the vibe check.\n"
        "\n"
        "Earl Grey Brownie Protocol:\n"
        "1. Brew one cup of Earl Grey.\n"
        "2. Add chocolate, butter and questionable judgment.\n"
        "3. Bake until the silicon exorcism is complete.\n"
        "\n"
        "No clients or CPU registers were harmed by this response.\n";
    ngx_buf_t *buffer;
    ngx_chain_t output;
    ngx_table_elt_t *header;
    ngx_int_t rc;

    buffer = ngx_calloc_buf(r->pool);
    if (buffer == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    header->hash = 1;
    ngx_str_set(&header->key, "X-Lumina-Verdict");
    ngx_str_set(&header->value, "Heresy-Detected");

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    header->hash = 1;
    ngx_str_set(&header->key, "X-Lumina-Wild-Wasteland");
    ngx_str_set(&header->value, "Enabled");

    r->headers_out.status = 418;
    ngx_str_set(&r->headers_out.status_line, "418 I'm a teapot");
    r->headers_out.content_length_n = sizeof(body) - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain; charset=utf-8");

    buffer->pos = body;
    buffer->last = body + sizeof(body) - 1;
    buffer->memory = 1;
    buffer->last_buf = (r == r->main);
    buffer->last_in_chain = 1;
    output.buf = buffer;
    output.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }
    rc = ngx_http_output_filter(r, &output);
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}
#endif

static ngx_int_t ngx_http_luminawaf_handler(ngx_http_request_t *r) {
    ngx_http_luminawaf_loc_conf_t *lcf;
    
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_luminawaf_module);

    if (lcf->enable == 0 || lcf->enable == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    if (r->unparsed_uri.len == 0) {
        return NGX_DECLINED;
    }

#ifdef LUMINA_WAF_DEBUG_TELEMETRY
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    LuminaBundle bundle;
    LuminaResult res;
    ngx_memzero(&bundle, sizeof(bundle));
    ngx_memzero(&res, sizeof(res));

    LuminaRuleState *state = ngx_pcalloc(r->pool, sizeof(LuminaRuleState));
    if (state == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_luminawaf_bundle_add(
        &bundle, &r->unparsed_uri, NULL, LUMINA_VAR_URI, LUMINA_SCOPE_URI, 0);
    ngx_http_luminawaf_bundle_add(
        &bundle, &r->args, NULL, LUMINA_VAR_ARGS, LUMINA_SCOPE_URI, 0);

    bundle.req_method = r->method_name.data;
    bundle.req_method_len = r->method_name.len;
    bundle.req_line = r->request_line.data;
    bundle.req_line_len = r->request_line.len;
    bundle.req_protocol = r->http_protocol.data;
    bundle.req_protocol_len = r->http_protocol.len;
    bundle.req_filename = r->uri.data;
    bundle.req_filename_len = r->uri.len;
    if (r->uri.data != NULL) {
        size_t basename_start = r->uri.len;
        while (basename_start > 0 && r->uri.data[basename_start - 1] != '/') {
            basename_start--;
        }
        bundle.req_basename = r->uri.data + basename_start;
        bundle.req_basename_len = r->uri.len - basename_start;
    }

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *headers = part->elts;
    for (ngx_uint_t i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            headers = part->elts;
            i = 0;
        }
        if (headers[i].hash != 0) {
            uint32_t header_mask = ngx_http_luminawaf_header_mask(&headers[i].key);
            ngx_http_luminawaf_count_header(&bundle, &headers[i]);
            if (header_mask == LUMINA_HDR_CONTENT_TYPE) {
                ngx_http_luminawaf_set_reqbody_processor(&bundle, &headers[i].value);
            }
            bundle.hdr_presence_mask |= header_mask;
            ngx_http_luminawaf_bundle_add(
                &bundle, &headers[i].value, &headers[i].key,
                header_mask == LUMINA_HDR_COOKIE ? LUMINA_VAR_COOKIE : LUMINA_VAR_HDR,
                LUMINA_SCOPE_HEADERS, header_mask);
        }
    }

    if (r->headers_in.user_agent != NULL) {
        bundle.user_agent = r->headers_in.user_agent->value.data;
        bundle.user_agent_len = r->headers_in.user_agent->value.len;
    }

    int inspect_result = luminawaf_inspect_bundle(&bundle, state, &res);
    ngx_http_luminawaf_add_origin_header(r);

#ifdef LUMINA_WAF_DEBUG_TELEMETRY
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long cost_us = (end.tv_sec - start.tv_sec) * 1000000LL + (end.tv_nsec - start.tv_nsec) / 1000LL;
    double cost_sec = (double)cost_us / 1000000.0;

    ngx_table_elt_t *h_time = ngx_list_push(&r->headers_in.headers);
    if (h_time != NULL) {
        h_time->hash = 1;
        ngx_str_set(&h_time->key, "X-Lumina-Time-Us");
        h_time->value.data = ngx_pnalloc(r->pool, 32);
        h_time->value.len = ngx_sprintf(h_time->value.data, "%.6f", cost_sec) - h_time->value.data;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "Lumina WAF: scanned uri=%.*s, threat=%d, err=%d", (int)r->unparsed_uri.len, r->unparsed_uri.data, res.threat_level, inspect_result);
#endif

    if (inspect_result == 0) {
        if (res.threat_level > 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "Lumina WAF: Blocked malicious request (threat_level=%d) uri=%.*s",
                          res.threat_level, (int)r->unparsed_uri.len, r->unparsed_uri.data);
            ngx_table_elt_t *h;
            h = ngx_list_push(&r->headers_out.headers);
            if (h != NULL) {
                h->hash = 1;
                ngx_str_set(&h->key, "X-Lumina-Rule-Id");
                h->value.data = ngx_pnalloc(r->pool, 16);
                h->value.len = ngx_sprintf(h->value.data, "%d", res.threat_level) - h->value.data;
            }
#ifdef LUMINA_WILD_WASTELAND
            return ngx_http_luminawaf_wild_response(r);
#else
            return NGX_HTTP_FORBIDDEN;
#endif
        }
    }

    return NGX_DECLINED;
}
