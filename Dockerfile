## Multi-stage build for http1.dev
##
## Usage:
##   # Build image (from repo root)
##   docker build -t http1-dev .
##
##   # Run CLI-style (ephemeral)
##   docker run --rm http1-dev http1 --help
##
##   # Run web UI on port 8080
##   docker run --rm -p 8080:8080 http1-dev

FROM golang:1.24 AS builder

WORKDIR /app

# Cache module download first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build a static-ish Linux binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /http1 ./cmd/http1

FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /http1 /usr/local/bin/http1
# Copy HTML templates needed by the web UI
COPY --from=builder /app/cmd/http1/templates /app/cmd/http1/templates

# Default to web mode on 8080 for convenience; override with args if desired.
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/http1"]
CMD ["--web", "8080"]

