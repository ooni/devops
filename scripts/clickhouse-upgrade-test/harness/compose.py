"""
Thin wrapper around `docker compose` so the rest of the harness doesn't
shell out directly. All commands run relative to PROJECT_DIR.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


def _file_args(files: list[str] | None) -> list[str]:
    """`-f a.yml -f b.yml ...`, or [] to fall back to compose's own default
    discovery of docker-compose.yml in PROJECT_DIR. Used by harness/real_data.py
    to layer docker-compose.real-data.yml on top of the base cluster
    definition without every other caller (the ch1/ch2/ch3 upgrade-mechanics
    functions below) having to know or care that overlay exists."""
    if not files:
        return []
    out = []
    for f in files:
        out += ["-f", f]
    return out


def _run(args: list[str], env: dict | None = None, check: bool = True, files: list[str] | None = None) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    proc = subprocess.run(
        ["docker", "compose", *_file_args(files), *args],
        cwd=PROJECT_DIR,
        env=full_env,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def up(services: list[str] | None = None, env: dict | None = None, force_recreate: bool = False, files: list[str] | None = None) -> None:
    args = ["up", "-d"]
    if force_recreate:
        args.append("--force-recreate")
    if services:
        args += ["--no-deps", *services]
    _run(args, env=env, files=files)


def down(volumes: bool = True, files: list[str] | None = None) -> None:
    args = ["down"]
    if volumes:
        args.append("-v")
    _run(args, check=False, files=files)


def logs(service: str, tail: int = 200, files: list[str] | None = None) -> str:
    proc = _run(["logs", f"--tail={tail}", service], check=False, files=files)
    return proc.stdout + proc.stderr


def run_oneoff(service: str, files: list[str] | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
    """`docker compose run --rm <service>` -- a fresh container + a fresh
    exit code every call, unlike `up -d` which only starts a service if it
    isn't already running. Used for the `verify` service in
    docker-compose.real-data.yml, invoked once per upgrade hop; each call
    must be an independent pass/fail, not a status read off a container
    left over from the previous hop's run."""
    full_env = os.environ.copy()
    proc = subprocess.run(
        ["docker", "compose", *_file_args(files), "run", "--rm", service],
        cwd=PROJECT_DIR,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc


def ps(files: list[str] | None = None) -> str:
    proc = _run(["ps"], check=False, files=files)
    return proc.stdout


def inspect_exit_code(container_name: str) -> int | None:
    """Exit code of a (possibly already-stopped) one-shot container, or None
    if the container doesn't exist / hasn't exited yet. Used to poll the
    `downloader`/`fastpath`/`verify` one-shot containers in
    docker-compose.real-data.yml, which use `service_completed_successfully`
    as their own dependency condition but whose actual pass/fail this
    harness still needs to observe and record."""
    proc = subprocess.run(
        ["docker", "inspect", container_name, "--format", "{{.State.Status}} {{.State.ExitCode}}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    status, _, code = proc.stdout.strip().partition(" ")
    if status != "exited":
        return None
    try:
        return int(code)
    except ValueError:
        return None


def upgrade_node(service: str, new_image_tag: str, current_env: dict) -> dict:
    """
    Recreate a single node with a new image tag while leaving the other
    nodes running untouched. `current_env` carries the *other* nodes' image
    pins forward (compose interpolates ${CH1_IMAGE} etc. from the process
    env / .env file at `up` time, so we must always pass the full set).

    Returns the updated env dict (with this service's image tag changed) so
    callers can thread it through subsequent calls.
    """
    var_name = f"{service.upper()}_IMAGE"
    new_env = dict(current_env)
    new_env[var_name] = new_image_tag
    up(services=[service], env=new_env, force_recreate=True)
    return new_env


def config_check(files: list[str] | None = None) -> str:
    """Validate compose file syntax/interpolation without contacting a registry."""
    proc = _run(["config"], check=True, files=files)
    return proc.stdout


def current_env() -> dict:
    """
    Reconstruct {"CH1_IMAGE": tag, "CH2_IMAGE": tag, "CH3_IMAGE": tag} by
    inspecting the already-running containers, rather than requiring a
    caller to thread an env dict through. This is what lets each upgrade
    step run as its own independent process (e.g. one `ci_step.py` CLI
    invocation per GitHub Actions step) while still knowing what image the
    *other* two nodes are currently on, without a side-channel state file
    that could drift from reality.

    A service with no running container yet (nothing brought up) is simply
    omitted -- callers fall back to docker-compose.yml's own defaults.
    """
    env = {}
    for i, svc in enumerate(["ch1", "ch2", "ch3"], start=1):
        proc = subprocess.run(
            ["docker", "inspect", f"ooni-{svc}", "--format", "{{.Config.Image}}"],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            image = proc.stdout.strip()
            tag = image.rsplit(":", 1)[-1] if ":" in image else image
            env[f"CH{i}_IMAGE"] = tag
    return env
