# syntax=docker/dockerfile:1
# Base images are pinned by digest; update the tag and digest together.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# alpine, not distroless: the organizer's harness `docker exec`s into containers
# to grep them, which needs a shell.
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN adduser -D -H -u 10001 app
COPY --from=build /out/server /usr/local/bin/server
USER 10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
