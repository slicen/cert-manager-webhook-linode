FROM golang:1.17-alpine AS build_deps

RUN apk add --no-cache git ca-certificates

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM scratch

COPY --from=build_deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
