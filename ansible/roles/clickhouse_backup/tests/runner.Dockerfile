# Debian bookworm's python3 and python3-boto3, as on the ClickHouse hosts
FROM docker.io/library/python:3.11-slim-bookworm
RUN pip install --no-cache-dir boto3==1.26.27 && mkdir -p /run/lock
