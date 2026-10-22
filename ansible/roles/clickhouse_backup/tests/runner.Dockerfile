# Debian bookworm with its python3 and python3-boto3, which the role installs on the ClickHouse hosts
FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-boto3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/lock
