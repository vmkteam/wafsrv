# Build binary
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git curl make
COPY . /build
RUN cd /build && make geo-download && CGO_ENABLED=0 go build -mod=vendor -o wafsrv ./cmd/wafsrv

# Final image
FROM alpine:latest

ENV TZ=Europe/Moscow
RUN apk --no-cache add ca-certificates tzdata && cp -r -f /usr/share/zoneinfo/$TZ /etc/localtime

COPY --from=builder /build/wafsrv /opt/wafsrv/wafsrv
COPY --from=builder /build/cfg/ /opt/wafsrv/cfg/

WORKDIR /opt/wafsrv
ENTRYPOINT ["/opt/wafsrv/wafsrv", "-config=cfg/local.toml", "-json"]
EXPOSE 8080 8081
