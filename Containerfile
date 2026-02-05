# Build stage
FROM docker.io/library/golang:1.25-alpine AS builder

WORKDIR /build

# Copy SDK first (needed for replace directive)
COPY sdk/ ./sdk/

# Copy server module
COPY server/go.mod server/go.sum ./server/
WORKDIR /build/server
RUN go mod download

# Copy server source
COPY server/ ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gateway ./cmd/gateway

# Runtime stage
FROM docker.io/library/alpine:3.21

RUN apk add --no-cache ca-certificates
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /gateway /usr/local/bin/gateway

USER appuser
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gateway"]
