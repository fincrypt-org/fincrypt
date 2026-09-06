# Multi-stage build: golang builder -> non-root alpine runtime.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server

FROM alpine:3.20
RUN adduser -D -H -u 10001 fincrypt
COPY --from=build /out/server /usr/local/bin/server
# Migrations ship inside the image so the container can boot a fresh DB.
COPY db/migrations /app/db/migrations
USER fincrypt
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]