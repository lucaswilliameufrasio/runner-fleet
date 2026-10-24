FROM node:24.22.1-trixie-slim AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN corepack pnpm install --frozen-lockfile
COPY web/ ./
RUN corepack pnpm run check && corepack pnpm run build
FROM golang:1.27.3-trixie AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o /server ./cmd/server
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/* && useradd -r -u 10001 -m fleet
COPY --from=server /server /usr/local/bin/runner-fleet-server
COPY --from=web /web/build /app/web
WORKDIR /app
USER 10001
ENTRYPOINT ["runner-fleet-server"]
