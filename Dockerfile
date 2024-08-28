# Building stage
FROM golang:1.21-alpine3.20 AS builder

WORKDIR /build
RUN adduser -u 10001 -D app-runner

#ENV GOPROXY https://goproxy.cn
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/reference/dockerfile/#copy
COPY *.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o ghgo

# Production stage
FROM alpine:3.20 AS final

WORKDIR /app
COPY --from=builder /build/ghgo /app/
#COPY --from=builder /build/config /app/config
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER app-runner
ENTRYPOINT ["/app/ghgo"]
EXPOSE 8888