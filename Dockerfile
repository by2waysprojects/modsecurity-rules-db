FROM --platform=$BUILDPLATFORM golang:1.22.4-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETARCH TARGETOS

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o modsecurity-rules-db ./cmd

FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/modsecurity-rules-db /usr/local/bin/modsecurity-rules-db

CMD ["/usr/local/bin/modsecurity-rules-db"]