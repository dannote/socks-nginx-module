FROM ubuntu:20.04

EXPOSE 80

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y wget build-essential libpcre3-dev zlib1g-dev gdb && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /root

COPY .gdbinit .

ARG NGX_VERSION

RUN wget https://nginx.org/download/nginx-$NGX_VERSION.tar.gz && \
    tar xzvf nginx-$NGX_VERSION.tar.gz && \
    rm nginx-$NGX_VERSION.tar.gz

WORKDIR nginx-$NGX_VERSION

CMD /bin/bash /code/debug/run.sh
