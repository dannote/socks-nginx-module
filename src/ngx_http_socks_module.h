
/*
 * Copyright (C) Danila Poyarkov
 *
 * Based on ngx_http_proxy_module.c
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_SOCKS_MODULE_H_INCLUDED_
#define _NGX_HTTP_SOCKS_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>

ngx_module_t  ngx_http_socks_module;

typedef struct {
    ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
} ngx_http_socks_main_conf_t;


typedef struct ngx_http_socks_rewrite_s  ngx_http_socks_rewrite_t;

typedef ngx_int_t (*ngx_http_socks_rewrite_pt)(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix, size_t len,
    ngx_http_socks_rewrite_t *pr);

struct ngx_http_socks_rewrite_s {
    ngx_http_socks_rewrite_pt      handler;

    union {
        ngx_http_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_http_regex_t          *regex;
#endif
    } pattern;

    ngx_http_complex_value_t       replacement;
};


typedef struct {
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_socks_vars_t;


typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_hash_t                     hash;
} ngx_http_socks_headers_t;


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *body_flushes;
    ngx_array_t                   *body_lengths;
    ngx_array_t                   *body_values;
    ngx_str_t                      body_source;

    ngx_http_socks_headers_t       headers;
#if (NGX_HTTP_CACHE)
    ngx_http_socks_headers_t       headers_cache;
#endif
    ngx_array_t                   *headers_source;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;

    ngx_str_t                      method;
    ngx_str_t                      location;
    ngx_str_t                      url;

    ngx_http_complex_value_t       host;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

    ngx_http_socks_vars_t          vars;

    ngx_flag_t                     redirect;

    ngx_uint_t                     http_version;

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

    ngx_str_t                      tunnel_header;
} ngx_http_socks_loc_conf_t;


typedef struct {
    ngx_http_status_t              status;
    ngx_http_chunked_t             chunked;
    ngx_http_socks_vars_t          vars;
    off_t                          internal_body_length;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    ngx_str_t                      host;

    unsigned                       head:1;
    unsigned                       internal_chunked:1;
    unsigned                       header_sent:1;
    unsigned                       tunnel:1;

    enum {
        socks_auth = 0,
        socks_connect,
        socks_done
    } state;
} ngx_http_socks_ctx_t;


ngx_int_t ngx_http_socks_upstream_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_socks_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_socks_upstream_create(ngx_http_request_t *r);
void ngx_http_socks_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_socks_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_socks_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_socks_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_socks_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#endif /* _NGX_HTTP_SOCKS_MODULE_H_INCLUDED_ */
