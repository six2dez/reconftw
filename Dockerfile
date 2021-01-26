FROM golang:1.15.7-alpine3.13
WORKDIR /app
ENV LANG="en_US.UTF-8" \
    LANGUAGE="en_US:en" \
    LC_ALL="en_US.UTF-8" \
    GOOS="linux" \
    GOPATH="/go" \
    GOROOT="/usr/local/go"
RUN apk add --update --no-cache bash python3 py3-pip sudo nmap && \
    apk add --no-cache --virtual .install-deps git gcc-go make libc-dev python3-dev libpcap-dev openssl-dev libxslt-dev libffi-dev libxml2-dev jq zlib-dev && \
    echo "Cloning reconftw repository..." && \
    git clone --depth 1 https://github.com/six2dez/reconftw.git -b main . &>/dev/null && \
    chmod +x install.sh && \
    echo "Installing dependencies..." && \
    bash -x ./install.sh &>/dev/null && \
    apk del .install-deps && \
    echo "Build finished!" && \
    echo "To run this container:" && \
    echo "" && \
    echo "docker run --rm reconftw/reconftw"
ADD . /app/
ENTRYPOINT ["/app/reconftw.sh"]
