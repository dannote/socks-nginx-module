#!/usr/bin/env bash

if [ ! -f /build/Makefile ]
then
  ./configure --with-debug --builddir=/build --add-dynamic-module=/code
fi

make -f /build/Makefile && gdb --args /build/nginx -c /code/debug/nginx.conf -p $PWD
