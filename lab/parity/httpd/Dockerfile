# lab/parity/httpd — deterministic HTTP target for the offline parity lab.
# Stdlib-only Go program; built statically and shipped on a tiny alpine base
# (busybox wget is used for the compose healthcheck).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY main.go .
# Standalone module: this directory has no go.mod of its own on purpose (it is
# part of the repo module for `go build ./lab/parity/httpd/`); inside the image
# we init a throwaway one because only main.go is copied.
RUN go mod init lab-httpd >/dev/null 2>&1 \
    && CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags='-s -w' -o /lab-httpd .

FROM alpine:3.21
COPY --from=build /lab-httpd /usr/local/bin/lab-httpd
# Runs unprivileged on 8080/8443; docker-compose publishes them as 80/443 on
# the host, which is what the recon engines probe.
RUN adduser -D -H -u 10001 lab
USER lab
EXPOSE 8080 8443
HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
    CMD wget -q -O /dev/null --header='Host: www.lab.test' http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/lab-httpd", "-http", ":8080", "-https", ":8443"]
