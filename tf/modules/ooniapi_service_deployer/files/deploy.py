#!/usr/bin/env python3
# Blue/green deploy for a single OONI API service, run by the
# ooniapi-<service>-deploy CodeBuild project (see ../main.tf and
# ./buildspec_deploy.yml). Stdlib only -- no pip installs, so the CodeBuild
# image needs nothing beyond python3, ssh/scp and the aws cli, all of which
# it already ships.
#
# For each of DEPLOY_HOST_PRIMARY/SECONDARY: find the currently idle slot
# (a/b) on that host, write that slot's secrets as individual files (picked
# up by the compose file's file-based `secrets:` entries -- the container
# only ever sees these mounted read-only at /run/secrets/<name>, never as
# environment variables), install & (re)start that slot's docker-compose.yaml
# at the new image tag, health-check it directly on its host port, then flip
# nginx's upstream to it and record the new active slot.
#
# Containers are started with `restart: always`, so the docker daemon
# itself keeps them running across crashes/reboots -- no systemd unit is
# needed on top of docker compose.

import json
import os
import subprocess
import sys
import tempfile
import time

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
    "-i", "/tmp/deploy_key",
]

# Private, deploy-user-owned (0700) directory files land in before being
# moved/installed into place -- not shared /tmp, so the env file (which
# carries service secrets) is never briefly world-readable on the target
# host. Must match ooniapi_gateway_staging_dir in the Ansible role.
STAGING_DIR = "/var/lib/ooniapi/deploy-staging"


def require_env(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"missing required environment variable: {name}")
    return value


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, text=True, **kwargs)


def ssh(user, host, remote_cmd):
    return run(["ssh", *SSH_OPTS, f"{user}@{host}", remote_cmd])


def ssh_output(user, host, remote_cmd):
    return run(["ssh", *SSH_OPTS, f"{user}@{host}", remote_cmd], capture_output=True).stdout


def ssh_succeeds(user, host, remote_cmd):
    return subprocess.run(["ssh", *SSH_OPTS, f"{user}@{host}", remote_cmd]).returncode == 0


def scp(user, host, local_path, remote_path):
    # -p preserves the local file's mode, so a locally-chmod'd-600 file
    # (e.g. the env file) lands on the target host already locked down
    # instead of briefly readable at whatever the remote umask would give it.
    run(["scp", *SSH_OPTS, "-p", local_path, f"{user}@{host}:{remote_path}"])


def s3_fetch(bucket, key):
    path = os.path.join(tempfile.gettempdir(), os.path.basename(key))
    run(["aws", "s3", "cp", f"s3://{bucket}/{key}", path])
    with open(path) as f:
        return f.read()


def secretsmanager_get(secret_arn):
    return run(
        ["aws", "secretsmanager", "get-secret-value", "--secret-id", secret_arn,
         "--query", "SecretString", "--output", "text"],
        capture_output=True,
    ).stdout


def write_tmp(name, content, mode=0o644):
    path = os.path.join(tempfile.gettempdir(), name)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)
    return path


def deploy_host(host, ctx):
    service = ctx["service"]
    user = ctx["user"]
    print(f"=== {service}: deploying to {host} ===")

    active_slot = ssh_output(
        user, host, f"cat /etc/ooniapi/{service}/active_slot 2>/dev/null || echo a"
    ).strip() or "a"
    target_slot = "b" if active_slot == "a" else "a"
    target_port = ctx["host_port_b"] if target_slot == "b" else ctx["host_port_a"]
    print(f"{service} on {host}: active slot is {active_slot}, deploying to slot {target_slot} (port {target_port})")

    # compose file for the target slot
    compose_file = f"{service}-{target_slot}.yaml"
    compose_path = f"/etc/ooniapi/{service}/{compose_file}"
    compose_content = s3_fetch(ctx["bucket"], f"{service}/{compose_file}")
    compose_content = compose_content.replace("__IMAGE_TAG__", ctx["image_tag"])
    compose_local = write_tmp(compose_file, compose_content)
    scp(user, host, compose_local, f"{STAGING_DIR}/{compose_file}")
    ssh(user, host, f"sudo mv {STAGING_DIR}/{compose_file} {compose_path}")

    # one file per secret, chmod'd 600 locally before scp -p sends it, then
    # installed straight to the path the compose file's `secrets:` section
    # references (install -D creates the slot's secrets/ dir on first use)
    for key, value in ctx["secrets"].items():
        secret_file = f"{service}-{target_slot}-{key}.secret"
        secret_local = write_tmp(secret_file, value, mode=0o600)
        secret_dest = f"/etc/ooniapi/{service}/{target_slot}/secrets/{key}"
        scp(user, host, secret_local, f"{STAGING_DIR}/{secret_file}")
        ssh(user, host,
            f"sudo install -D -m 600 -o root -g root {STAGING_DIR}/{secret_file} {secret_dest}"
            f" && rm -f {STAGING_DIR}/{secret_file}")

    ssh(user, host, f"sudo docker compose -f {compose_path} up -d --pull always --remove-orphans")

    healthy = False
    for _ in range(10):
        if ssh_succeeds(user, host, f"curl -sf -o /dev/null http://127.0.0.1:{target_port}/health"):
            healthy = True
            break
        time.sleep(2)
    if not healthy:
        sys.exit(f"{service} on {host}: slot {target_slot} failed health check, aborting deploy")

    state_a, state_b = ("", "down") if target_slot == "a" else ("down", "")
    upstream_file = f"{service}-upstream.conf"
    upstream_content = s3_fetch(ctx["bucket"], f"{service}/{upstream_file}")
    upstream_content = upstream_content.replace("__STATE_A__", state_a).replace("__STATE_B__", state_b)
    upstream_local = write_tmp(upstream_file, upstream_content)
    scp(user, host, upstream_local, f"{STAGING_DIR}/{upstream_file}")
    ssh(user, host,
        f"sudo mv {STAGING_DIR}/{upstream_file} /etc/nginx/conf.d/{upstream_file}"
        f" && sudo nginx -t && sudo systemctl reload nginx")
    ssh(user, host, f"echo {target_slot} | sudo tee /etc/ooniapi/{service}/active_slot > /dev/null")

    print(f"=== {service} on {host}: now serving from slot {target_slot} ===")


def main():
    with open("imagedefinitions.json") as f:
        image_tag = json.load(f)[0]["imageUri"].rsplit(":", 1)[-1]

    service = require_env("SERVICE_NAME")
    print(f"Deploying {service} image tag {image_tag}")

    with open("/tmp/deploy_key", "w") as f:
        f.write(secretsmanager_get(require_env("DEPLOY_SSH_KEY_SECRET_ARN")))
    os.chmod("/tmp/deploy_key", 0o600)

    ctx = {
        "service": service,
        "user": require_env("DEPLOY_SSH_USER"),
        "bucket": require_env("DEPLOY_BUCKET"),
        "image_tag": image_tag,
        "host_port_a": require_env("HOST_PORT_A"),
        "host_port_b": require_env("HOST_PORT_B"),
        "secrets": json.loads(secretsmanager_get(require_env("SERVICE_SECRETS_ARN"))),
    }

    for host in (require_env("DEPLOY_HOST_PRIMARY"), require_env("DEPLOY_HOST_SECONDARY")):
        deploy_host(host, ctx)


if __name__ == "__main__":
    main()
