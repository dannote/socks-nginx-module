# socks-nginx-module

An nginx module that adds SOCKS5 proxy support to `proxy_pass`.

## Features

- Route upstream traffic through a SOCKS5 proxy
- Username/password authentication (RFC 1929)
- SSL to upstream through the SOCKS tunnel (`proxy_pass https://...`)
- IPv4, IPv6, and domain name address types

## Building

Requires nginx **1.26.x** and PCRE2.

```bash
git clone https://github.com/dannote/socks-nginx-module
wget http://nginx.org/download/nginx-1.26.3.tar.gz
tar -xzf nginx-1.26.3.tar.gz
cd nginx-1.26.3

./configure --add-dynamic-module=../socks-nginx-module
make
make install
```

## Directives

### `socks_pass`

Specifies the SOCKS5 proxy to route upstream traffic through. Must follow a `proxy_pass` directive.

```nginx
socks_pass socks5://proxy:1080;
```

Credentials can be provided inline:

```nginx
socks_pass socks5://user:password@proxy:1080;
```

### `socks_username` / `socks_password`

Set SOCKS5 authentication credentials separately from the URL.

```nginx
socks_pass socks5://proxy:1080;
socks_username myuser;
socks_password mypassword;
```

## Configuration examples

### HTTP through SOCKS

```nginx
location / {
    proxy_pass http://httpbin.org/get;
    socks_pass socks5://proxy:1080;
}
```

### HTTPS through SOCKS

```nginx
location / {
    proxy_pass https://httpbin.org/get;
    proxy_ssl_server_name on;
    socks_pass socks5://proxy:1080;
}
```

### With authentication

```nginx
location / {
    proxy_pass http://httpbin.org/get;
    socks_pass socks5://user:password@proxy:1080;
}
```

## Development

### Running tests

```bash
make ci
```

Individual targets: `build`, `build-clang`, `build-asan`, `test`, `test-asan`, `lint`, `cppcheck`, `format`.

### Debugging

```bash
cd debug
docker compose run --service-ports nginx

(gdb) set follow-fork-mode child
(gdb) run
```
