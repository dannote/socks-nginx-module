#!/usr/bin/env bash

if [ ! -f /build/Makefile ]
then
  ./configure --with-debug --with-http_ssl_module --builddir=/build --add-dynamic-module=/code
fi

make -f /build/Makefile

ulimit -c unlimited
echo '/tmp/core.%e.%p' > /proc/sys/kernel/core_pattern 2>/dev/null || true
/build/nginx -c /code/debug/nginx.conf -p $PWD -g "daemon off;"
