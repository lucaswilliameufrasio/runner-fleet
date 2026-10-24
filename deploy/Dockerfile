FROM node:24-bookworm-slim AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build
FROM golang:1.25.1-bookworm AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o /server ./cmd/server
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* && useradd -r -u 10001 -m fleet
COPY --from=server /server /usr/local/bin/runner-fleet-server
COPY --from=web /web/build /app/web
WORKDIR /app
USER 10001
ENTRYPOINT ["runner-fleet-server"]
