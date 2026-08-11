"""
Thin wrapper around `docker compose` so the rest of the harness doesn't
shell out directly. All commands run relative to PROJECT_DIR.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


def _run(args: list[str], env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    proc = subprocess.run(
        ["docker", "compose", *args],
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


def up(services: list[str] | None = None, env: dict | None = None, force_recreate: bool = False) -> None:
    args = ["up", "-d"]
    if force_recreate:
        args.append("--force-recreate")
    if services:
        args += ["--no-deps", *services]
    _run(args, env=env)


def down(volumes: bool = True) -> None:
    args = ["down"]
    if volumes:
        args.append("-v")
    _run(args, check=False)


def logs(service: str, tail: int = 200) -> str:
    proc = _run(["logs", f"--tail={tail}", service], check=False)
    return proc.stdout + proc.stderr


def ps() -> str:
    proc = _run(["ps"], check=False)
    return proc.stdout


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


def config_check() -> str:
    """Validate compose file syntax/interpolation without contacting a registry."""
    proc = _run(["config"], check=True)
    return proc.stdout
