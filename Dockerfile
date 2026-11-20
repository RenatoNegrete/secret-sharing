# syntax=docker/dockerfile:1
FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# alpine, not distroless: the organizer's harness `docker exec`s into containers
# to grep them, which needs a shell.
FROM alpine:3.22
RUN adduser -D -H -u 10001 app
COPY --from=build /out/server /usr/local/bin/server
USER 10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]
