# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder
WORKDIR /src
# go.mod uses remote replace directive for auth-client, no local copy needed
# Build context is the service directory root
COPY go.mod go.sum ./
RUN GOTOOLCHAIN=auto go mod download
COPY . .
RUN GOTOOLCHAIN=auto CGO_ENABLED=0 go build -o /out/treasury ./cmd/api

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /out/treasury /app/service
# TLS certificates directory (optional, can be mounted as volume)
# Note: distroless doesn't support RUN, so certs must be mounted as volume
USER nonroot:nonroot
EXPOSE 4001
ENV PORT=4001
ENTRYPOINT ["/app/service"]
