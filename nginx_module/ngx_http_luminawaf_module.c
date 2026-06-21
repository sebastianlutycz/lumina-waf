#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

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

static ngx_int_t ngx_http_luminawaf_handler(ngx_http_request_t *r) {
    ngx_http_luminawaf_loc_conf_t *lcf;
    
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_luminawaf_module);

    if (lcf->enable == 0 || lcf->enable == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    if (r->unparsed_uri.len == 0) {
        return NGX_DECLINED;
    }

    LuminaResult res;
    if (luminawaf_inspect_request(r->unparsed_uri.data, r->unparsed_uri.len, &res) == 0) {
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
            return NGX_HTTP_FORBIDDEN;
        }
    }

    return NGX_DECLINED;
}
