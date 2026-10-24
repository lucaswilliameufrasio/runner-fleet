FROM ubuntu:24.04
ARG TARGETARCH
ARG RUNNER_VERSION
ARG RUNNER_SHA256_AMD64
ARG RUNNER_SHA256_ARM64
ENV DEBIAN_FRONTEND=noninteractive RUNNER_ALLOW_RUNAS_ROOT=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git jq python3 unzip zip build-essential libicu74 libssl3t64 zlib1g libkrb5-3 liblttng-ust1 && rm -rf /var/lib/apt/lists/*
WORKDIR /runner
RUN test -n "$RUNNER_VERSION" && case "$TARGETARCH" in amd64) arch=x64; sum="$RUNNER_SHA256_AMD64";; arm64) arch=arm64; sum="$RUNNER_SHA256_ARM64";; *) exit 1;; esac && test ${#sum} -eq 64 && curl -fsSL "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${arch}-${RUNNER_VERSION}.tar.gz" -o /tmp/runner.tgz && echo "$sum  /tmp/runner.tgz" | sha256sum -c - && tar xzf /tmp/runner.tgz && rm /tmp/runner.tgz
COPY entrypoint.py hook-start.sh hook-end.sh /runner/
RUN chmod 755 /runner/hook-start.sh /runner/hook-end.sh
ENV ACTIONS_RUNNER_HOOK_JOB_STARTED=/runner/hook-start.sh ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/runner/hook-end.sh
ENTRYPOINT ["python3","/runner/entrypoint.py"]
