FROM ubuntu:24.04

EXPOSE 80

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        wget curl build-essential \
        libpcre2-dev zlib1g-dev libssl-dev \
        clang clang-tidy clang-format \
        cppcheck gdb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

COPY .gdbinit .

ARG NGX_VERSION=1.26.3

RUN wget -q https://nginx.org/download/nginx-$NGX_VERSION.tar.gz && \
    tar xzf nginx-$NGX_VERSION.tar.gz && \
    rm nginx-$NGX_VERSION.tar.gz

WORKDIR nginx-$NGX_VERSION

CMD /bin/bash /code/debug/run.sh
