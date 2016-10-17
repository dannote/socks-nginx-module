# socks-nginx-module

An `nginx_http_proxy_module` fork with SOCKS5 support

## Building

nginx >= **1.9.1** is supported.

```bash
# apt-get install git build-essential zlib1g-dev libpcre3 libpcre3-dev unzip

$ git clone https://github.com/dannote/socks-nginx-module
$ wget http://nginx.org/download/nginx-1.9.15.tar.gz

$ tar -xzvf nginx-1.9.15.tar.gz

$ cd nginx-1.9.15

# See http://nginx.org/en/docs/configure.html for more configuration options
$ ./configure --add-module=../socks-nginx-module

$ make
# make install
```

## Configuring

Sample HTTP to SOCKS5 proxy configuration:

```
location / {
  socks_set_header Host $http_host;
  socks_set_header Proxy-Connection '';
  socks_pass_header Server;
  socks_redirect off;
  socks_http_version 1.1;
  socks_tunnel_header X-Connect;
  socks_buffers 16 16k; 
  socks_buffer_size 32k;
  socks_cache proxy;
  socks_cache_valid 30s;
  socks_cache_use_stale error timeout invalid_header updating
                        http_500 http_502 http_503 http_504;
  socks_pass socks5://127.0.0.1:1080;
}
```

All [ngx_http_proxy_module](http://nginx.org/en/docs/http/ngx_http_proxy_module.html) directives are supported.

### socks_tunnel_header

Context: `http`, `server`, `location`

As nginx HTTP parser doesn't support HTTP CONNECT method, a special header can be set to indicate tunnel connection.

This directive can be exploited with the following HAProxy configuration:

```
frontend local
  bind *:8080
  mode http
  http-request set-method GET if METH_CONNECT
  http-request set-uri https://%[req.hdr(Host)]/ if METH_CONNECT
  http-request add-header X-Connect true if METH_CONNECT
  default_backend nginx

backend nginx
  mode http
  server proxy 127.0.0.1:8080 maxconn 100000
```

### socks_set_host

Context: `http`, `server`, `location`

Default: `proxy_set_host $http_host;`

Overrides the endpoint server.

This example will proxy requests to `ipinfo.io` via local Tor daemon:

```
location /ip {
  socks_pass socks5://127.0.0.1:9050;
  socks_set_host ipinfo.io;
  socks_set_header Host ipinfo.io; 
  socks_redirect off;
  socks_http_version 1.1;
}
```