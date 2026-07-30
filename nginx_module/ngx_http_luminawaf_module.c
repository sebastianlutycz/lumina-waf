#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>

#include <luminawaf.h>

typedef struct {
    ngx_flag_t  enable;
} ngx_http_luminawaf_loc_conf_t;

#define NGX_HTTP_LUMINAWAF_CAPTURE_SLAB_SIZE  (16u * 1024u)

typedef enum {
    NGX_HTTP_LUMINAWAF_BODY_DIRECT = 0,
    NGX_HTTP_LUMINAWAF_BODY_CAPTURE_EXACT,
    NGX_HTTP_LUMINAWAF_BODY_CAPTURE_SLABS
} ngx_http_luminawaf_body_mode_t;

typedef struct ngx_http_luminawaf_capture_slab_s
    ngx_http_luminawaf_capture_slab_t;

struct ngx_http_luminawaf_capture_slab_s {
    ngx_http_luminawaf_capture_slab_t *next;
    u_char                            *data;
    size_t                             used;
};

typedef struct {
    ngx_int_t                           status;
    ngx_http_luminawaf_body_mode_t      body_mode;
    u_char                             *capture_data;
    size_t                              capture_capacity;
    size_t                              captured;
    ngx_http_luminawaf_capture_slab_t  *capture_head;
    ngx_http_luminawaf_capture_slab_t  *capture_tail;
    int                                 threat_level;
} ngx_http_luminawaf_ctx_t;

static ngx_int_t ngx_http_luminawaf_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_luminawaf_init(ngx_conf_t *cf);
static void *ngx_http_luminawaf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_luminawaf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_luminawaf_init_process(ngx_cycle_t *cycle);
static void ngx_http_luminawaf_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_luminawaf_request_body_filter(
    ngx_http_request_t *r, ngx_chain_t *in);
static void ngx_http_luminawaf_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_luminawaf_inspect(
    ngx_http_request_t *r, const ngx_str_t *body, int *threat_level);
static ngx_int_t ngx_http_luminawaf_materialize_body(
    ngx_http_request_t *r, ngx_http_luminawaf_ctx_t *ctx, ngx_str_t *body);
static ngx_int_t ngx_http_luminawaf_handle_verdict(
    ngx_http_request_t *r, int threat_level);
#ifdef LUMINA_WILD_WASTELAND
static ngx_int_t ngx_http_luminawaf_wild_response(ngx_http_request_t *r);
#endif

static ngx_http_request_body_filter_pt
    ngx_http_luminawaf_next_request_body_filter;

static ngx_inline ngx_int_t
ngx_http_luminawaf_bundle_add(LuminaBundle *bundle, const ngx_str_t *value,
                              const ngx_str_t *name,
                              LuminaVarType var_type, uint32_t scope,
                              uint32_t header_mask)
{
    BundleVar *var;

    if (value == NULL || value->data == NULL ||
        (value->len == 0 && name == NULL)) {
        return NGX_OK;
    }
    if (bundle->count >= LUMINA_BUNDLE_MAX_VARS) {
        return NGX_ERROR;
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
    return NGX_OK;
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

    ngx_http_luminawaf_next_request_body_filter =
        ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter =
        ngx_http_luminawaf_request_body_filter;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_luminawaf_handler;
    return NGX_OK;
}

static ngx_int_t ngx_http_luminawaf_init_process(ngx_cycle_t *cycle) {
    if (luminawaf_init_worker(4096) != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "LuminaWAF worker initialization failed");
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

static ngx_inline ngx_flag_t
ngx_http_luminawaf_content_encoding_supported(ngx_http_request_t *r)
{
    static u_char content_encoding[] = "Content-Encoding";
    static u_char identity[] = "identity";
    ngx_list_part_t *part;
    ngx_table_elt_t *headers;

    part = &r->headers_in.headers.part;
    headers = part->elts;

    for (ngx_uint_t i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            headers = part->elts;
            i = 0;
        }
        if (headers[i].hash == 0 ||
            headers[i].key.len != sizeof(content_encoding) - 1 ||
            ngx_strncasecmp(headers[i].key.data, content_encoding,
                            sizeof(content_encoding) - 1) != 0) {
            continue;
        }

        u_char *start = headers[i].value.data;
        u_char *end = start + headers[i].value.len;
        while (start < end && (*start == ' ' || *start == '\t')) start++;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if ((size_t)(end - start) != sizeof(identity) - 1 ||
            ngx_strncasecmp(start, identity, sizeof(identity) - 1) != 0) {
            return 0;
        }
    }
    return 1;
}

static ngx_int_t
ngx_http_luminawaf_capture_append(ngx_http_request_t *r,
                                  ngx_http_luminawaf_ctx_t *ctx,
                                  const u_char *data, size_t len)
{
    if (ctx->captured > LUMINA_MAX_INSPECTED_VALUE ||
        len > LUMINA_MAX_INSPECTED_VALUE - ctx->captured) {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    if (ctx->body_mode == NGX_HTTP_LUMINAWAF_BODY_CAPTURE_EXACT) {
        if (len > ctx->capture_capacity - ctx->captured) {
            return NGX_HTTP_BAD_REQUEST;
        }
        ngx_memcpy(ctx->capture_data + ctx->captured, data, len);
        ctx->captured += len;
        return NGX_OK;
    }

    while (len != 0) {
        ngx_http_luminawaf_capture_slab_t *slab = ctx->capture_tail;
        if (slab == NULL || slab->used == NGX_HTTP_LUMINAWAF_CAPTURE_SLAB_SIZE) {
            slab = ngx_pcalloc(r->pool, sizeof(*slab));
            if (slab == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            slab->data = ngx_pnalloc(r->pool,
                                     NGX_HTTP_LUMINAWAF_CAPTURE_SLAB_SIZE);
            if (slab->data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if (ctx->capture_tail != NULL) {
                ctx->capture_tail->next = slab;
            } else {
                ctx->capture_head = slab;
            }
            ctx->capture_tail = slab;
        }

        size_t available = NGX_HTTP_LUMINAWAF_CAPTURE_SLAB_SIZE - slab->used;
        size_t copy = len < available ? len : available;
        ngx_memcpy(slab->data + slab->used, data, copy);
        slab->used += copy;
        ctx->captured += copy;
        data += copy;
        len -= copy;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_luminawaf_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_luminawaf_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_luminawaf_module);
    if (ctx != NULL && ctx->status == NGX_DONE &&
        ctx->body_mode != NGX_HTTP_LUMINAWAF_BODY_DIRECT) {
        for (ngx_chain_t *cl = in; cl != NULL; cl = cl->next) {
            ngx_buf_t *buffer = cl->buf;
            size_t len;
            ngx_int_t rc;

            if (buffer == NULL || ngx_buf_special(buffer)) {
                continue;
            }
            if (!ngx_buf_in_memory(buffer) || buffer->last < buffer->pos) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            len = (size_t)(buffer->last - buffer->pos);
            if (len == 0) {
                continue;
            }
            rc = ngx_http_luminawaf_capture_append(
                r, ctx, buffer->pos, len);
            if (rc != NGX_OK) {
                ngx_log_error(
                    NGX_LOG_WARN, r->connection->log, 0,
                    "LuminaWAF request-body capture failed: "
                    "status=%i captured=%uz incoming=%uz mode=%ui",
                    rc, ctx->captured, len, (ngx_uint_t)ctx->body_mode);
                return rc;
            }
        }
    }

    return ngx_http_luminawaf_next_request_body_filter(r, in);
}

static ngx_int_t
ngx_http_luminawaf_materialize_body(ngx_http_request_t *r,
                                    ngx_http_luminawaf_ctx_t *ctx,
                                    ngx_str_t *body)
{
    ngx_chain_t *cl;
    u_char *single = NULL;
    size_t total = 0;
    ngx_uint_t buffers = 0;

    body->data = NULL;
    body->len = 0;

    if (ctx->body_mode == NGX_HTTP_LUMINAWAF_BODY_CAPTURE_EXACT) {
        if (ctx->captured != ctx->capture_capacity) {
            return NGX_HTTP_BAD_REQUEST;
        }
        body->data = ctx->capture_data;
        body->len = ctx->captured;
        return NGX_OK;
    }

    if (ctx->body_mode == NGX_HTTP_LUMINAWAF_BODY_CAPTURE_SLABS) {
        if (ctx->captured == 0) {
            return NGX_OK;
        }
        if (ctx->capture_head == ctx->capture_tail) {
            body->data = ctx->capture_head->data;
            body->len = ctx->capture_head->used;
            return NGX_OK;
        }

        body->data = ngx_pnalloc(r->pool, ctx->captured);
        if (body->data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        u_char *write = body->data;
        for (ngx_http_luminawaf_capture_slab_t *slab = ctx->capture_head;
             slab != NULL; slab = slab->next) {
            write = ngx_cpymem(write, slab->data, slab->used);
        }
        body->len = ctx->captured;
        return NGX_OK;
    }

    if (r->request_body == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *buffer = cl->buf;
        size_t len;

        if (buffer == NULL || ngx_buf_special(buffer)) {
            continue;
        }
        if (buffer->in_file || !ngx_buf_in_memory(buffer) ||
            buffer->last < buffer->pos) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        len = (size_t)(buffer->last - buffer->pos);
        if (len == 0) {
            continue;
        }
        if (len > LUMINA_MAX_INSPECTED_VALUE - total) {
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
        if (buffers == 0) {
            single = buffer->pos;
        }
        total += len;
        buffers++;
    }

    if (r->headers_in.content_length_n >= 0 &&
        (off_t)total != r->headers_in.content_length_n) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (buffers == 0) {
        return NGX_OK;
    }
    if (buffers == 1) {
        body->data = single;
        body->len = total;
        return NGX_OK;
    }

    body->data = ngx_pnalloc(r->pool, total);
    if (body->data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    u_char *write = body->data;
    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        ngx_buf_t *buffer = cl->buf;
        if (buffer != NULL && ngx_buf_in_memory(buffer) &&
            buffer->last > buffer->pos) {
            write = ngx_cpymem(write, buffer->pos,
                               (size_t)(buffer->last - buffer->pos));
        }
    }
    body->len = total;
    return NGX_OK;
}

static ngx_int_t
ngx_http_luminawaf_inspect(ngx_http_request_t *r, const ngx_str_t *body,
                           int *threat_level)
{
    LuminaBundle bundle;
    LuminaResult result;
    LuminaRuleState state;
    ngx_list_part_t *part;
    ngx_table_elt_t *headers;

#ifdef LUMINA_WAF_DEBUG_TELEMETRY
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    ngx_memzero(&bundle, sizeof(bundle));
    ngx_memzero(&result, sizeof(result));
    ngx_memzero(&state, sizeof(state));

    if (ngx_http_luminawaf_bundle_add(
            &bundle, &r->unparsed_uri, NULL, LUMINA_VAR_URI,
            LUMINA_SCOPE_URI, 0) != NGX_OK ||
        ngx_http_luminawaf_bundle_add(
            &bundle, &r->args, NULL, LUMINA_VAR_ARGS,
            LUMINA_SCOPE_URI, 0) != NGX_OK ||
        (body != NULL && body->len != 0 &&
         ngx_http_luminawaf_bundle_add(
             &bundle, body, NULL, LUMINA_VAR_BODY,
             LUMINA_SCOPE_BODY, 0) != NGX_OK)) {
        return NGX_HTTP_REQUEST_HEADER_TOO_LARGE;
    }

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

    part = &r->headers_in.headers.part;
    headers = part->elts;
    for (ngx_uint_t i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            headers = part->elts;
            i = 0;
        }
        if (headers[i].hash != 0) {
            uint32_t header_mask =
                ngx_http_luminawaf_header_mask(&headers[i].key);
            ngx_http_luminawaf_count_header(&bundle, &headers[i]);
            if (header_mask == LUMINA_HDR_CONTENT_TYPE) {
                ngx_http_luminawaf_set_reqbody_processor(
                    &bundle, &headers[i].value);
            }
            bundle.hdr_presence_mask |= header_mask;
            if (ngx_http_luminawaf_bundle_add(
                    &bundle, &headers[i].value, &headers[i].key,
                    header_mask == LUMINA_HDR_COOKIE
                        ? LUMINA_VAR_COOKIE : LUMINA_VAR_HDR,
                    LUMINA_SCOPE_HEADERS, header_mask) != NGX_OK) {
                ngx_log_error(
                    NGX_LOG_WARN, r->connection->log, 0,
                    "LuminaWAF bundle capacity exceeded: capacity=%d",
                    LUMINA_BUNDLE_MAX_VARS);
                return NGX_HTTP_REQUEST_HEADER_TOO_LARGE;
            }
        }
    }

    if (r->headers_in.user_agent != NULL) {
        bundle.user_agent = r->headers_in.user_agent->value.data;
        bundle.user_agent_len = r->headers_in.user_agent->value.len;
    }

    int inspect_result =
        luminawaf_inspect_bundle(&bundle, &state, &result);
    if (inspect_result != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (result.error_flag == LUMINA_ERROR_REQBODY_MALFORMED) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (result.error_flag == LUMINA_ERROR_REQBODY_UNSUPPORTED) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    if (result.error_flag == LUMINA_ERROR_REQBODY_LIMIT) {
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    if (result.error_flag == LUMINA_ERROR_REQBODY_FORBIDDEN) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (result.error_flag != LUMINA_ERROR_NONE) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    *threat_level = result.threat_level;

#ifdef LUMINA_WAF_DEBUG_TELEMETRY
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long cost_us = (end.tv_sec - start.tv_sec) * 1000000LL
                        + (end.tv_nsec - start.tv_nsec) / 1000LL;
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "Lumina WAF: scanned uri=%.*s, threat=%d, cost_us=%L",
                  (int)r->unparsed_uri.len, r->unparsed_uri.data,
                  result.threat_level, cost_us);
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_luminawaf_handle_verdict(ngx_http_request_t *r, int threat_level)
{
    ngx_http_luminawaf_add_origin_header(r);
    if (threat_level <= 0) {
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "Lumina WAF: Blocked malicious request "
                  "(threat_level=%d) uri=%V",
                  threat_level, &r->unparsed_uri);

    ngx_table_elt_t *header = ngx_list_push(&r->headers_out.headers);
    if (header != NULL) {
        header->hash = 1;
        ngx_str_set(&header->key, "X-Lumina-Rule-Id");
        header->value.data = ngx_pnalloc(r->pool, 16);
        if (header->value.data != NULL) {
            header->value.len = ngx_sprintf(
                header->value.data, "%d", threat_level) - header->value.data;
        } else {
            header->hash = 0;
        }
    }

#ifdef LUMINA_WILD_WASTELAND
    return ngx_http_luminawaf_wild_response(r);
#else
    return NGX_HTTP_FORBIDDEN;
#endif
}

static void
ngx_http_luminawaf_body_handler(ngx_http_request_t *r)
{
    ngx_http_luminawaf_ctx_t *ctx;
    ngx_str_t body;
    ngx_int_t rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_luminawaf_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc = ngx_http_luminawaf_materialize_body(r, ctx, &body);
    if (rc == NGX_OK) {
        rc = ngx_http_luminawaf_inspect(r, &body, &ctx->threat_level);
    }
    if (rc == NGX_OK) {
        ctx->status = ctx->threat_level > 0
                          ? NGX_HTTP_FORBIDDEN : NGX_DECLINED;
    } else {
        ngx_log_error(
            NGX_LOG_WARN, r->connection->log, 0,
            "LuminaWAF request-body completion failed: "
            "status=%i captured=%uz mode=%ui",
            rc, ctx->captured, (ngx_uint_t)ctx->body_mode);
        ctx->status = rc;
    }

    r->preserve_body = 1;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}

static ngx_int_t
ngx_http_luminawaf_handler(ngx_http_request_t *r)
{
    ngx_http_luminawaf_loc_conf_t *lcf;
    ngx_http_luminawaf_ctx_t *ctx;
    ngx_http_core_loc_conf_t *clcf;
    ngx_int_t rc;
    int threat_level = 0;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_luminawaf_module);
    if (lcf->enable == 0 || lcf->enable == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }
    if (r->unparsed_uri.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_luminawaf_module);
    if (ctx != NULL) {
        if (ctx->status == NGX_DONE) {
            return NGX_DONE;
        }
        if (ctx->status == NGX_DECLINED ||
            (ctx->status == NGX_HTTP_FORBIDDEN &&
             ctx->threat_level > 0)) {
            return ngx_http_luminawaf_handle_verdict(
                r, ctx->threat_level);
        }
        return ctx->status;
    }

    if (r != r->main ||
        (!r->headers_in.chunked &&
         r->headers_in.content_length_n <= 0)) {
        rc = ngx_http_luminawaf_inspect(r, NULL, &threat_level);
        if (rc != NGX_OK) {
            return rc;
        }
        return ngx_http_luminawaf_handle_verdict(r, threat_level);
    }

    if (r->headers_in.content_length_n > (off_t)LUMINA_MAX_INSPECTED_VALUE) {
        ngx_log_error(
            NGX_LOG_WARN, r->connection->log, 0,
            "LuminaWAF request body exceeds inspection limit: "
            "length=%O limit=%uD",
            r->headers_in.content_length_n,
            (uint32_t)LUMINA_MAX_INSPECTED_VALUE);
        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    if (!ngx_http_luminawaf_content_encoding_supported(r)) {
        ngx_log_error(
            NGX_LOG_WARN, r->connection->log, 0,
            "LuminaWAF rejected unsupported request content encoding");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->status = NGX_DONE;
    ctx->body_mode = NGX_HTTP_LUMINAWAF_BODY_DIRECT;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (r->headers_in.content_length_n < 0) {
        ctx->body_mode = NGX_HTTP_LUMINAWAF_BODY_CAPTURE_SLABS;
    } else if (r->request_body_in_file_only ||
               (off_t)clcf->client_body_buffer_size <
                   r->headers_in.content_length_n) {
        ctx->body_mode = NGX_HTTP_LUMINAWAF_BODY_CAPTURE_EXACT;
        ctx->capture_capacity =
            (size_t)r->headers_in.content_length_n;
        ctx->capture_data = ngx_pnalloc(
            r->pool, ctx->capture_capacity);
        if (ctx->capture_data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_http_set_ctx(r, ctx, ngx_http_luminawaf_module);
    r->request_body_in_single_buf = 1;

    rc = ngx_http_read_client_request_body(
        r, ngx_http_luminawaf_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}
