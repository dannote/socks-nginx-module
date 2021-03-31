# socks-nginx-module

An `nginx_http_proxy_module` fork with SOCKS5 support

## Building

nginx >= **1.18.0** is supported.

```bash
# apt-get install git build-essential zlib1g-dev libpcre3 libpcre3-dev unzip

$ git clone https://github.com/dannote/socks-nginx-module
$ wget http://nginx.org/download/nginx-1.18.0.tar.gz

$ tar -xzvf nginx-1.18.0.tar.gz

$ cd nginx-1.18.0

# See http://nginx.org/en/docs/configure.html for more configuration options
$ ./configure --add-dynamic-module=../socks-nginx-module

$ make
# make install
```

## Configuring

Sample HTTP to SOCKS5 proxy configuration:

```
location / {
  proxy_pass http://httpbin.org/get;
  socks_pass socks5://proxy:1080;
}
```

## Debugging

```
cd debug
docker-compose run --service-ports nginx

(gdb) set follow-fork-mode child
(gdb) run
```