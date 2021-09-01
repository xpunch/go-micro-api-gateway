FROM golang:latest AS builder

WORKDIR /micro

COPY . /micro

RUN pwd && \
    go env -w GOPROXY=https://goproxy.cn,direct && \
    go build -a -installsuffix cgo -ldflags "-s -w ${LDFLAGS}" -o api-gateway

FROM alpine:latest

COPY --from=builder /micro/api-gateway /usr/local/bin/api-gateway

RUN chmod +x /usr/local/bin/api-gateway

CMD ["/usr/local/bin/api-gateway"]