/*
 * Copyright (C) Danila Poyarkov
 */


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

#include "ngx_http_proxy_module.h"
#include "ngx_http_socks_upstream.h"

#pragma GCC diagnostic pop


#define NGX_HTTP_SOCKS_VERSION                0x05
#define NGX_HTTP_SOCKS_RESERVED               0x00
#define NGX_HTTP_SOCKS_AUTH_NO_AUTHENTICATION 0x00
#define NGX_HTTP_SOCKS_AUTH_USERNAME_PASSWORD 0x02
#define NGX_HTTP_SOCKS_AUTH_NO_ACCEPTABLE     0xFF
#define NGX_HTTP_SOCKS_AUTH_SUBNEG_VERSION    0x01
#define NGX_HTTP_SOCKS_CMD_CONNECT            0x01
#define NGX_HTTP_SOCKS_ADDR_IPv4              0x01
#define NGX_HTTP_SOCKS_ADDR_IPv6              0x04
#define NGX_HTTP_SOCKS_ADDR_DOMAIN_NAME       0x03

#define NGX_HTTP_SOCKS_MAX_RESPONSE_LEN 263


typedef struct {
    ngx_str_t schema;
    ngx_str_t host;
    ngx_str_t port;
    ngx_str_t uri;
} ngx_http_socks_vars_t;


typedef struct {
    ngx_http_upstream_conf_t upstream;
    ngx_str_t url;
    ngx_http_socks_vars_t vars;
    ngx_str_t username;
    ngx_str_t password;
    ngx_array_t *proxy_lengths;
    ngx_array_t *proxy_values;
} ngx_http_socks_loc_conf_t;


typedef struct {
    ngx_http_socks_vars_t vars;

    enum {
        socks_auth = 0,
        socks_auth_response,
        socks_userpass,
        socks_userpass_response,
        socks_connect,
        socks_connect_response,
        socks_done
    } state;

    u_char buf[NGX_HTTP_SOCKS_MAX_RESPONSE_LEN];
    size_t received;
    size_t response_len;
} ngx_http_socks_ctx_t;


static ngx_int_t
ngx_http_socks_eval(ngx_http_request_t *r, ngx_http_socks_ctx_t *ctx,
                    ngx_http_socks_loc_conf_t *plcf);
static char *
ngx_http_socks_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_socks_upstream_init(ngx_http_request_t *r);
static void ngx_http_socks_upstream_init_request(ngx_http_request_t *r);
static void
ngx_http_socks_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void
ngx_http_socks_upstream_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void
ngx_http_socks_send_auth(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_socks_read_auth_response(ngx_http_request_t *r,
                                              ngx_http_upstream_t *u);
static void
ngx_http_socks_send_userpass(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_socks_read_userpass_response(ngx_http_request_t *r,
                                                  ngx_http_upstream_t *u);
static void
ngx_http_socks_send_connect(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_socks_read_connect_response(ngx_http_request_t *r,
                                                 ngx_http_upstream_t *u);
static void
ngx_http_socks_handshake_done(ngx_http_request_t *r, ngx_http_upstream_t *u);

static ngx_int_t
ngx_http_socks_host_variable(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http_socks_port_variable(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_socks_add_variables(ngx_conf_t *cf);
static void *ngx_http_socks_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_socks_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static void ngx_http_socks_set_vars(ngx_url_t *u, ngx_http_socks_vars_t *v);


static ngx_command_t ngx_http_socks_commands[] = {

    {ngx_string("socks_pass"),
     NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_http_socks_pass, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

    {ngx_string("socks_username"),
     NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_socks_loc_conf_t, username), NULL},

    {ngx_string("socks_password"),
     NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_socks_loc_conf_t, password), NULL},

    ngx_null_command};


static ngx_http_variable_t ngx_http_socks_vars[] = {

    {ngx_string("socks_host"), NULL, ngx_http_socks_host_variable, 0,
     NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
     0},

    {ngx_string("socks_port"), NULL, ngx_http_socks_port_variable, 0,
     NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
     0},

    ngx_http_null_variable};


static char *ngx_http_socks_errors[] =
    {"unknown error",
     "general failure",
     "connection not allowed by ruleset",
     "network unreachable",
     "host unreachable",
     "connection refused by destination host",
     "TTL expired",
     "command not supported",
     "address type not supported"};


static ngx_http_module_t ngx_http_socks_module_ctx = {
    ngx_http_socks_add_variables, /* preconfiguration */
    NULL,                         /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_socks_create_loc_conf, /* create location configuration */
    ngx_http_socks_merge_loc_conf   /* merge location configuration */
};


ngx_module_t ngx_http_socks_module =
    {NGX_MODULE_V1,
     &ngx_http_socks_module_ctx, /* module context */
     ngx_http_socks_commands,    /* module directives */
     NGX_HTTP_MODULE,            /* module type */
     NULL,                       /* init master */
     NULL,                       /* init module */
     NULL,                       /* init process */
     NULL,                       /* init thread */
     NULL,                       /* exit thread */
     NULL,                       /* exit process */
     NULL,                       /* exit master */
     NGX_MODULE_V1_PADDING};


static ngx_int_t
ngx_http_socks_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_upstream_t *u;
    ngx_http_socks_ctx_t *sctx;
    ngx_http_proxy_ctx_t *pctx;
    ngx_http_proxy_loc_conf_t *plcf;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_main_conf_t *pmcf;
#endif
    ngx_http_socks_loc_conf_t *slcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    pctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
    if (pctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, pctx, ngx_http_proxy_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
        pctx->vars = plcf->vars;
        u->schema = plcf->vars.schema;
#if (NGX_HTTP_SSL)
        u->ssl = plcf->ssl;
#endif
    }
    else {
        if (ngx_http_proxy_eval(r, pctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    sctx = ngx_pcalloc(r->pool, sizeof(ngx_http_socks_ctx_t));
    if (sctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, sctx, ngx_http_socks_module);

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_socks_module);

    if (slcf->proxy_lengths == NULL) {
        sctx->vars = slcf->vars;
    }
    else {
        if (ngx_http_socks_eval(r, sctx, slcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (ngx_buf_tag_t) &ngx_http_socks_module;

    /*
     * Copy proxy upstream conf into socks upstream conf to inherit all
     * timeout and buffer settings, then override the upstream pointer
     * so that the TCP connection goes to the SOCKS proxy, not the target.
     */
    {
        ngx_http_upstream_srv_conf_t *socks_uscf;

        socks_uscf = slcf->upstream.upstream;
        slcf->upstream = plcf->upstream;
        slcf->upstream.upstream = socks_uscf;
    }

    u->conf = &slcf->upstream;

#if (NGX_HTTP_CACHE)
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_http_proxy_create_key;
#endif

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_status_line;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;
    r->state = 0;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_copy_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_proxy_input_filter_init;
    u->input_filter = ngx_http_proxy_non_buffered_copy_filter;
    u->input_filter_ctx = r;

    u->accel = 1;

    if (!plcf->upstream.request_buffering && plcf->body_values == NULL &&
        plcf->upstream.pass_request_body &&
        (!r->headers_in.chunked || plcf->http_version == NGX_HTTP_VERSION_11)) {
        r->request_body_no_buffering = 1;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_socks_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static char *
ngx_http_socks_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_short port;
    ngx_str_t *value, *url;
    ngx_url_t u;
    ngx_uint_t n;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_proxy_loc_conf_t *plcf;
    ngx_http_socks_loc_conf_t *slcf = conf;
    ngx_http_script_compile_t sc;

    if (slcf->proxy_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_socks_handler;

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &slcf->proxy_lengths;
        sc.values = &slcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "socks5://",
                        sizeof("socks5://") - 1) == 0) {
        port = 1080;
    }
    else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - sizeof("socks5://") + 1;
    u.url.data = url->data + sizeof("socks5://") - 1;

    {
        u_char *at, *colon, *end;

        at = ngx_strlchr(u.url.data, u.url.data + u.url.len, '@');

        if (at) {
            colon = ngx_strlchr(u.url.data, at, ':');
            end = u.url.data + u.url.len;

            if (colon) {
                slcf->username.len = colon - u.url.data;
                slcf->username.data =
                    ngx_pstrdup(cf->pool,
                                &(ngx_str_t){slcf->username.len, u.url.data});

                slcf->password.len = at - colon - 1;
                slcf->password.data =
                    ngx_pstrdup(cf->pool,
                                &(ngx_str_t){slcf->password.len, colon + 1});
            }
            else {
                slcf->username.len = at - u.url.data;
                slcf->username.data =
                    ngx_pstrdup(cf->pool,
                                &(ngx_str_t){slcf->username.len, u.url.data});
            }

            u.url.len = end - at - 1;
            u.url.data = at + 1;
        }
    }

    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    slcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (slcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    slcf->vars.schema.len = sizeof("socks5://") - 1;
    slcf->vars.schema.data = url->data;

    ngx_http_socks_set_vars(&u, &slcf->vars);

    plcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

    if (plcf->upstream.upstream == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"socks_pass\" must be preceded "
                           "by \"proxy_pass\" directive");
        return NGX_CONF_ERROR;
    }

    slcf->url = *url;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_socks_eval(ngx_http_request_t *r, ngx_http_socks_ctx_t *ctx,
                    ngx_http_socks_loc_conf_t *slcf)
{
    u_short port;
    ngx_str_t proxy;
    ngx_url_t url;
    ngx_http_upstream_t *u;

    if (ngx_http_script_run(r, &proxy, slcf->proxy_lengths->elts, 0,
                            slcf->proxy_values->elts) == NULL) {
        return NGX_ERROR;
    }

    if (proxy.len > sizeof("socks5://") - 1 &&
        ngx_strncasecmp(proxy.data, (u_char *) "socks5://",
                        sizeof("socks5://") - 1) == 0) {
        port = 1080;
    }
    else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid URL prefix in \"%V\"", &proxy);
        return NGX_ERROR;
    }

    u = r->upstream;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = proxy.len - sizeof("socks5://") + 1;
    url.url.data = proxy.data + sizeof("socks5://") - 1;
    url.default_port = port;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    ngx_http_socks_set_vars(&url, &ctx->vars);

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}


static void
ngx_http_socks_upstream_init(ngx_http_request_t *r)
{
    ngx_connection_t *c;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks init upstream, client timer: %d",
                   c->read->timer_set);

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_socks_upstream_init_request(r);
        return;
    }
#endif

#if (NGX_HTTP_V3)
    if (r->http_version == NGX_HTTP_VERSION_30) {
        ngx_http_socks_upstream_init_request(r);
        return;
    }
#endif

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) ==
                NGX_ERROR) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    ngx_http_socks_upstream_init_request(r);
}


static void
ngx_http_socks_upstream_init_request(ngx_http_request_t *r)
{
    ngx_str_t *host;
    ngx_uint_t i;
    ngx_resolver_ctx_t *ctx, temp;
    ngx_http_cleanup_t *cln;
    ngx_http_upstream_t *u;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_upstream_srv_conf_t *uscf, **uscfp;
    ngx_http_upstream_main_conf_t *umcf;

    if (r->aio) {
        return;
    }

    u = r->upstream;

#if (NGX_HTTP_CACHE)

    if (u->conf->cache) {
        ngx_int_t rc;

        rc = ngx_http_upstream_cache(r, u);

        if (rc == NGX_BUSY) {
            r->write_event_handler = ngx_http_socks_upstream_init_request;
            return;
        }

        r->write_event_handler = ngx_http_request_empty_handler;

        if (rc == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == NGX_OK) {
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_DECLINED;
                r->cached = 0;
                u->buffer.start = NULL;
                u->cache_status = NGX_HTTP_CACHE_MISS;
                u->request_sent = 1;
            }
        }

        if (rc != NGX_DECLINED) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

#endif

    u->store = u->conf->store;

    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
        r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
        r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_upstream_set_local(r, u, u->conf->local) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;

    if (u->output.output_filter == NULL) {
        u->output.output_filter = ngx_chain_writer;
        u->output.filter_ctx = &u->writer;
    }

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {
        r->upstream_states =
            ngx_array_create(r->pool, 1, sizeof(ngx_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }
    else {
        u->state = ngx_array_push(r->upstream_states);
        if (u->state == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;
    }
    else {
#if (NGX_HTTP_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->host.len == host->len &&
                ((uscf->port == 0 && u->resolved->no_port) ||
                 uscf->port == u->resolved->port) &&
                ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0) {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {
            if (u->resolved->port == 0 &&
                u->resolved->sockaddr->sa_family != AF_UNIX) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_http_upstream_finalize_request(
                    r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_http_upstream_create_round_robin_peer(r, u->resolved) !=
                NGX_OK) {
                ngx_http_upstream_finalize_request(
                    r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_http_socks_upstream_connect(r, u);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->handler = ngx_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "no upstream configuration");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NGX_HTTP_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(r, uscf) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries &&
        u->peer.tries > u->conf->next_upstream_tries) {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    ngx_http_socks_upstream_connect(r, u);
}


static void
ngx_http_socks_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t rc;
    ngx_connection_t *c;
    ngx_http_core_loc_conf_t *clcf;

    r->connection->log->action = "connecting to upstream";

    if (u->state && u->state->response_time == (ngx_msec_t) -1) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(r->upstream_states);
    if (u->state == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->response_time = (ngx_msec_t) -1;
    u->state->connect_time = (ngx_msec_t) -1;
    u->state->header_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http socks upstream connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    c = u->peer.connection;

    c->requests++;

    c->data = r;

    c->write->handler = ngx_http_upstream_handler;
    c->read->handler = ngx_http_upstream_handler;

    u->write_event_handler = ngx_http_socks_upstream_handler;
    u->read_event_handler = ngx_http_socks_upstream_handler;

    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;

    if (r->connection->tcp_nopush == NGX_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }

    if (c->pool == NULL) {
        c->pool = ngx_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    u->writer.limit = clcf->sendfile_max_chunk;

    if (u->request_sent) {
        if (ngx_http_upstream_reinit(r, u) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (r->request_body && r->request_body->buf && r->request_body->temp_file &&
        r == r->main) {
        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;

        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }

    u->request_sent = 0;
    u->request_body_sent = 0;
    u->request_body_blocked = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    ngx_http_socks_send_auth(r, u);
}


static void
ngx_http_socks_upstream_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks upstream handler, state: %d", ctx->state);

    if (c->write->timedout || c->read->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    switch (ctx->state) {
    case socks_auth:
        ngx_http_socks_send_auth(r, u);
        break;

    case socks_auth_response:
        ngx_http_socks_read_auth_response(r, u);
        break;

    case socks_userpass:
        ngx_http_socks_send_userpass(r, u);
        break;

    case socks_userpass_response:
        ngx_http_socks_read_userpass_response(r, u);
        break;

    case socks_connect:
        ngx_http_socks_send_connect(r, u);
        break;

    case socks_connect_response:
        ngx_http_socks_read_connect_response(r, u);
        break;

    case socks_done:
        break;
    }
}


static void
ngx_http_socks_send_auth(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t n;
    u_char msg[4];
    size_t len;
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;
    ngx_http_socks_loc_conf_t *slcf;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_socks_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http socks send auth");

    msg[0] = NGX_HTTP_SOCKS_VERSION;

    if (slcf->username.len) {
        msg[1] = 2;
        msg[2] = NGX_HTTP_SOCKS_AUTH_NO_AUTHENTICATION;
        msg[3] = NGX_HTTP_SOCKS_AUTH_USERNAME_PASSWORD;
        len = 4;
    }
    else {
        msg[1] = 1;
        msg[2] = NGX_HTTP_SOCKS_AUTH_NO_AUTHENTICATION;
        len = 3;
    }

    n = c->send(c, msg, len);

    if (n == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        ctx->state = socks_auth;
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    ctx->state = socks_auth_response;
    ctx->received = 0;

    if (c->read->ready) {
        ngx_http_socks_read_auth_response(r, u);
        return;
    }

    ngx_add_timer(c->read, u->conf->connect_timeout);
}


static void
ngx_http_socks_read_auth_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t n;
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks read auth response");

    n = c->recv(c, ctx->buf + ctx->received, 2 - ctx->received);

    if (n == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "SOCKS proxy closed connection during auth");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    ctx->received += n;

    if (ctx->received < 2) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    if (ctx->buf[0] != NGX_HTTP_SOCKS_VERSION) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "invalid SOCKS protocol version: %d", ctx->buf[0]);
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (ctx->buf[1] == NGX_HTTP_SOCKS_AUTH_USERNAME_PASSWORD) {
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        ngx_http_socks_send_userpass(r, u);
        return;
    }

    if (ctx->buf[1] != NGX_HTTP_SOCKS_AUTH_NO_AUTHENTICATION) {
        if (ctx->buf[1] == NGX_HTTP_SOCKS_AUTH_NO_ACCEPTABLE) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "SOCKS proxy: no acceptable auth methods");
        }
        else {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "SOCKS proxy selected unsupported auth method: "
                          "0x%02xd",
                          ctx->buf[1]);
        }
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_http_socks_send_connect(r, u);
}


static void
ngx_http_socks_send_userpass(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t n;
    u_char *buf, *p;
    size_t len;
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;
    ngx_http_socks_loc_conf_t *slcf;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_socks_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http socks send userpass");

    if (slcf->username.len == 0 || slcf->username.len > 255 ||
        slcf->password.len > 255) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "SOCKS auth: invalid username/password length");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    /*
     * RFC 1929 username/password sub-negotiation:
     *   byte 0: version (0x01)
     *   byte 1: username length
     *   bytes:  username
     *   byte:   password length
     *   bytes:  password
     */
    len = 1 + 1 + slcf->username.len + 1 + slcf->password.len;

    buf = ngx_pnalloc(r->pool, len);
    if (buf == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    p = buf;
    *p++ = NGX_HTTP_SOCKS_AUTH_SUBNEG_VERSION;
    *p++ = (u_char) slcf->username.len;
    p = ngx_cpymem(p, slcf->username.data, slcf->username.len);
    *p++ = (u_char) slcf->password.len;
    p = ngx_cpymem(p, slcf->password.data, slcf->password.len);

    n = c->send(c, buf, len);

    ngx_pfree(r->pool, buf);

    if (n == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        ctx->state = socks_userpass;
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    ctx->state = socks_userpass_response;
    ctx->received = 0;

    if (c->read->ready) {
        ngx_http_socks_read_userpass_response(r, u);
        return;
    }

    ngx_add_timer(c->read, u->conf->connect_timeout);
}


static void
ngx_http_socks_read_userpass_response(ngx_http_request_t *r,
                                      ngx_http_upstream_t *u)
{
    ssize_t n;
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks read userpass response");

    n = c->recv(c, ctx->buf + ctx->received, 2 - ctx->received);

    if (n == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "SOCKS proxy closed connection during "
                      "username/password auth");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    ctx->received += n;

    if (ctx->received < 2) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    if (ctx->buf[0] != NGX_HTTP_SOCKS_AUTH_SUBNEG_VERSION) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "invalid SOCKS auth sub-negotiation version: %d",
                      ctx->buf[0]);
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (ctx->buf[1] != 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "SOCKS username/password authentication failed");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks userpass auth successful");

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_http_socks_send_connect(r, u);
}


static void
ngx_http_socks_send_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t n;
    u_char *buf, *p;
    in_addr_t inaddr;
    size_t len;
    ngx_uint_t port;
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;
    ngx_http_proxy_ctx_t *pctx;
    ngx_str_t host;
#if (NGX_HAVE_INET6)
    u_char addr6[16];
#endif

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);
    pctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http socks send connect");

    host = pctx->vars.host_header;

    if (host.len == 0 || host.len > 0xFF) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid target host length");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    port = ngx_atoi(pctx->vars.port.data, pctx->vars.port.len);

    /*
     * Detect address type: try parsing as IPv4, IPv6, or domain name.
     * RFC 1928 address types:
     *   0x01 = IPv4 (4 bytes)
     *   0x03 = domain name (1-byte length + data)
     *   0x04 = IPv6 (16 bytes)
     */
    inaddr = ngx_inet_addr(host.data, host.len);

    if (inaddr != INADDR_NONE) {
        /* IPv4 address: 4 header + 4 addr + 2 port */
        len = 10;

        buf = ngx_pnalloc(r->pool, len);
        if (buf == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        p = buf;
        *p++ = NGX_HTTP_SOCKS_VERSION;
        *p++ = NGX_HTTP_SOCKS_CMD_CONNECT;
        *p++ = NGX_HTTP_SOCKS_RESERVED;
        *p++ = NGX_HTTP_SOCKS_ADDR_IPv4;
        p = ngx_cpymem(p, &inaddr, 4);

#if (NGX_HAVE_INET6)
    }
    else if (host.len > 2 && host.data[0] == '[' &&
             host.data[host.len - 1] == ']') {
        ngx_str_t v6str;

        v6str.data = host.data + 1;
        v6str.len = host.len - 2;

        if (ngx_inet6_addr(v6str.data, v6str.len, addr6) == NGX_OK) {
            /* IPv6 address: 4 header + 16 addr + 2 port */
            len = 22;

            buf = ngx_pnalloc(r->pool, len);
            if (buf == NULL) {
                ngx_http_upstream_finalize_request(
                    r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            p = buf;
            *p++ = NGX_HTTP_SOCKS_VERSION;
            *p++ = NGX_HTTP_SOCKS_CMD_CONNECT;
            *p++ = NGX_HTTP_SOCKS_RESERVED;
            *p++ = NGX_HTTP_SOCKS_ADDR_IPv6;
            p = ngx_cpymem(p, addr6, 16);
        }
        else {
            goto domain;
        }
#endif
    }
    else {
#if (NGX_HAVE_INET6)
    domain:
#endif
        /* domain name: 4 header + 1 length + name + 2 port */
        len = host.len + 7;

        buf = ngx_pnalloc(r->pool, len);
        if (buf == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        p = buf;
        *p++ = NGX_HTTP_SOCKS_VERSION;
        *p++ = NGX_HTTP_SOCKS_CMD_CONNECT;
        *p++ = NGX_HTTP_SOCKS_RESERVED;
        *p++ = NGX_HTTP_SOCKS_ADDR_DOMAIN_NAME;
        *p++ = (u_char) host.len;
        p = ngx_cpymem(p, host.data, host.len);
    }

    *p++ = (u_char) (port >> 8);
    *p++ = (u_char) (port & 0xFF);

    n = c->send(c, buf, len);

    ngx_pfree(r->pool, buf);

    if (n == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        ctx->state = socks_connect;
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

    ctx->state = socks_connect_response;
    ctx->received = 0;
    ctx->response_len = 0;

    if (c->read->ready) {
        ngx_http_socks_read_connect_response(r, u);
        return;
    }

    ngx_add_timer(c->read, u->conf->connect_timeout);
}


static void
ngx_http_socks_read_connect_response(ngx_http_request_t *r,
                                     ngx_http_upstream_t *u)
{
    ssize_t n;
    size_t need;
    ngx_connection_t *c;
    ngx_http_socks_ctx_t *ctx;

    c = u->peer.connection;
    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks read connect response, received: %uz",
                   ctx->received);

    /*
     * SOCKS5 connect response format:
     *   byte 0: version (0x05)
     *   byte 1: reply (0x00 = success)
     *   byte 2: reserved (0x00)
     *   byte 3: address type
     *   bytes 4+: address + port (variable length)
     *
     * We first need 5 bytes to determine the address type and thus
     * the total response length, then read the rest.
     */

    if (ctx->response_len == 0) {
        need = 5;
    }
    else {
        need = ctx->response_len;
    }

    n = c->recv(c, ctx->buf + ctx->received, need - ctx->received);

    if (n == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (n == NGX_AGAIN) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "SOCKS proxy closed connection during connect");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    ctx->received += n;

    if (ctx->received < 5) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    if (ctx->buf[0] != NGX_HTTP_SOCKS_VERSION) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "invalid SOCKS protocol version: %d", ctx->buf[0]);
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (ctx->buf[1] != 0) {
        if (ctx->buf[1] <
            sizeof(ngx_http_socks_errors) / sizeof(ngx_http_socks_errors[0])) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "SOCKS error: %s",
                          ngx_http_socks_errors[ctx->buf[1]]);
        }
        else {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "SOCKS error: unknown (%d)",
                          ctx->buf[1]);
        }
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (ctx->response_len == 0) {
        switch (ctx->buf[3]) {
        case NGX_HTTP_SOCKS_ADDR_IPv4:
            /* 4 bytes header + 4 bytes IPv4 + 2 bytes port */
            ctx->response_len = 10;
            break;

        case NGX_HTTP_SOCKS_ADDR_IPv6:
            /* 4 bytes header + 16 bytes IPv6 + 2 bytes port */
            ctx->response_len = 22;
            break;

        case NGX_HTTP_SOCKS_ADDR_DOMAIN_NAME:
            /* 4 bytes header + 1 byte length + domain + 2 bytes port */
            ctx->response_len = 4 + 1 + ctx->buf[4] + 2;
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "unsupported SOCKS address type: %d", ctx->buf[3]);
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        if (ctx->response_len > NGX_HTTP_SOCKS_MAX_RESPONSE_LEN) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "SOCKS response too large: %uz", ctx->response_len);
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }
    }

    if (ctx->received < ctx->response_len) {
        ngx_add_timer(c->read, u->conf->connect_timeout);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http socks upstream connected");

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ctx->state = socks_done;

    ngx_http_socks_handshake_done(r, u);
}


static void
ngx_http_socks_handshake_done(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, u->peer.connection->log, 0,
                   "http socks handshake done");

#if (NGX_HTTP_SSL)

    if (u->ssl && u->peer.connection->ssl == NULL) {
        ngx_connection_t *c;
        ngx_http_proxy_ctx_t *pctx;

        c = u->peer.connection;
        pctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

        /*
         * Override ssl_name with the target hostname so that TLS SNI
         * and certificate verification use the correct name, not the
         * SOCKS proxy hostname.
         */
        if (pctx != NULL && pctx->vars.host_header.len) {
            u->ssl_name = pctx->vars.host_header;
        }

        /*
         * Set upstream event handlers before SSL init, because the
         * async SSL handshake completion path calls
         * ngx_http_upstream_send_request() which expects the standard
         * read/write event handlers to be in place.
         */
        u->write_event_handler = ngx_http_upstream_send_request_handler;
        u->read_event_handler = ngx_http_upstream_process_header;

        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    u->write_event_handler = ngx_http_upstream_send_request_handler;
    u->read_event_handler = ngx_http_upstream_process_header;

    ngx_http_upstream_send_request(r, u, 1);
}


static ngx_int_t
ngx_http_socks_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_socks_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_socks_host_variable(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_socks_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.host.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_socks_port_variable(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_socks_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_socks_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NGX_OK;
}


static void *
ngx_http_socks_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_socks_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_socks_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_socks_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_socks_loc_conf_t *prev = parent;
    ngx_http_socks_loc_conf_t *conf = child;

    if (conf->proxy_lengths == NULL) {
        conf->vars = prev->vars;
        conf->proxy_lengths = prev->proxy_lengths;
        conf->proxy_values = prev->proxy_values;
    }

    ngx_conf_merge_str_value(conf->username, prev->username, "");
    ngx_conf_merge_str_value(conf->password, prev->password, "");

    return NGX_CONF_OK;
}


static void
ngx_http_socks_set_vars(ngx_url_t *u, ngx_http_socks_vars_t *v)
{
    if (u->family != AF_UNIX) {
        if (u->no_port || u->port == u->default_port) {
            v->host = u->host;
            ngx_str_set(&v->port, "1080");
        }
        else {
            v->host.len = u->host.len + 1 + u->port_text.len;
            v->host.data = u->host.data;
            v->port = u->port_text;
        }
    }
    else {
        ngx_str_set(&v->host, "localhost");
        ngx_str_null(&v->port);
    }

    v->uri = u->uri;
}
