FROM golang:1.15.7-alpine3.13
ARG RECONFTW_VERSION=0.9-beta1
WORKDIR /app
ENV LANG="en_US.UTF-8" \
    LANGUAGE="en_US:en" \
    LC_ALL="en_US.UTF-8" \
    GOOS="linux" \
    GOPATH="/go" \
    GOROOT="/usr/local/go"
RUN apk add --update --no-cache bash python3 py3-pip sudo nmap && \
    apk add --no-cache --virtual .install-deps git gcc-go make libc-dev python3-dev libpcap-dev openssl-dev libxslt-dev libffi-dev libxml2-dev zlib-dev && \
    git clone --depth 1 https://github.com/six2dez/reconftw.git -b $RECONFTW_VERSION . && \
    chmod +x install.sh && \
    bash -x ./install.sh && \
    apk del .install-deps
ENTRYPOINT ["/app/reconftw.sh"]
