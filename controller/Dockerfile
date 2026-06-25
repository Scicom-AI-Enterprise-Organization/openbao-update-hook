# Multi-stage: build a static binary, ship it on scratch (tiny, fast cold start).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /audit-resync .

FROM scratch
# CA bundle so we can verify the k8s API server (we also pin the SA CA at runtime).
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /audit-resync /audit-resync
EXPOSE 9000
ENTRYPOINT ["/audit-resync"]
