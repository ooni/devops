#!/usr/bin/env python3
"""
Rolls a ClickHouse version bump out across the cluster with the role, one host at a time,
as an operator would: deploy FROM_VERSION to three Debian hosts named like the production
replicas (compose.yml), with the real group and host vars (secrets replaced by test values),
then set clickhouse_version to TO_VERSION and deploy each host with --limit, in turn.

After each host it checks that the role succeeded, that the host's ClickHouse runs
TO_VERSION under systemd with its packages pinned to it, and that every node still answers
and reaches Keeper; and it reports what the cluster looks like in between: each node's
version and Keeper role, and how many of the inserts made meanwhile failed (mixed-version
errors are expected for some hops; see ooni/devops#477). At the end every
node must run TO_VERSION, have no read-only or failing replicated tables, and have every
row whose insert succeeded.

The hosts start with the apt source line the role's upstream version left (no signed-by),
as production's do. FROM_VERSION defaults to production's clickhouse_version, TO_VERSION to
next_version. Called by run.sh; needs ansible-playbook with community.docker, and PyYAML.
"""
import os, re, shutil, subprocess, sys, threading, time
import yaml

TESTS = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.normpath(os.path.join(TESTS, "../../../.."))
REPO = os.path.dirname(ANSIBLE)
OUT = os.path.join(TESTS, "out")
INV = os.path.join(OUT, "inventory")
COMPOSE = os.environ.get("COMPOSE", "docker compose").split() + ["-f", os.path.join(TESTS, "compose.yml")]
NODES = {"data1": "data1.htz-fsn.prod.ooni.nu", "data2": "data2.htz-fsn.prod.ooni.nu",
         "data3": "data3.htz-fsn.prod.ooni.nu"}
ADMIN_CONFIG = "/etc/clickhouse-client/ansible-admin.xml"  # written by the role
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


# --- inventory: production's vars, with the version the test sets ------------------------

def secrets_replaced(text):
    return re.sub(r"lookup\('amazon\.aws\.aws_(?:ssm|secret)', '([^']+)'[^)]*\)",
                  lambda m: "'test-" + m.group(1).rsplit("/", 1)[-1] + "'", text)


def write_inventory():
    shutil.rmtree(INV, ignore_errors=True)
    os.makedirs(os.path.join(INV, "group_vars"))
    os.makedirs(os.path.join(INV, "host_vars"))
    for src, dst in (("group_vars/all/vars.yml", "group_vars/all.yml"),
                     ("group_vars/clickhouse/vars.yml", "group_vars/clickhouse.yml")):
        open(os.path.join(INV, dst), "w").write(secrets_replaced(open(os.path.join(ANSIBLE, src)).read()))
    for node, host in NODES.items():
        src = os.path.join(ANSIBLE, "host_vars", host)
        text = secrets_replaced(open(src).read()) if os.path.isfile(src) else ""
        text += f"\nansible_connection: community.docker.docker\nansible_host: chupgrade-{node}\n"
        open(os.path.join(INV, "host_vars", host + ".yml"), "w").write(text)
    open(os.path.join(INV, "hosts.ini"), "w").write("[clickhouse]\n" + "\n".join(NODES.values()) + "\n")


def set_version(version):
    """clickhouse_version in the group vars, as the version bump in a PR would change it."""
    p = os.path.join(INV, "group_vars/clickhouse.yml")
    text, n = re.subn(r"^clickhouse_version: .*$", f"clickhouse_version: {version}", open(p).read(), flags=re.M)
    assert n == 1
    open(p, "w").write(text)


def deploy(label, limit=None, args=()):
    hosts = [n for n, h in NODES.items() if limit in (None, h)]
    for n in hosts:  # the packages downloaded by earlier hosts
        sh(n, "cp -n /debs/*.deb /var/cache/apt/archives/ 2>/dev/null; true")
    cmd = ["ansible-playbook", "-i", os.path.join(INV, "hosts.ini"), os.path.join(TESTS, "deploy.yml"), *args]
    if limit:
        cmd += ["--limit", limit]
    env = dict(os.environ, ANSIBLE_ROLES_PATH=os.path.join(ANSIBLE, "roles"), ANSIBLE_NOCOLOR="1",
               SCHEMA=os.path.join(REPO, "scripts/cluster-migration/schema.sql"))
    started = time.time()
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    open(os.path.join(OUT, f"ansible-{label}.log"), "w").write(r.stdout + r.stderr)
    for n in hosts:
        sh(n, "cp -n /var/cache/apt/archives/*.deb /debs/ 2>/dev/null; true")
    if r.returncode:
        print(r.stdout[-4000:] + r.stderr[-1500:])
    return r.returncode, time.time() - started


# --- the hosts -----------------------------------------------------------------------------

def podman_noise_removed(stderr):
    """stderr without the notices of podman's docker emulation, if that's what runs compose"""
    noise = ("Emulate Docker CLI", "Executing external compose provider", "Error: executing ")
    return "\n".join(l for l in stderr.splitlines() if not any(n in l for n in noise) and l.strip("\x1b[0m ")).strip()


def sh(node, command, timeout=60):
    r = subprocess.run(COMPOSE + ["exec", "-T", node, "bash", "-c", command], capture_output=True,
                       text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), podman_noise_removed(r.stderr)


def sql(node, query, timeout=60):
    r = subprocess.run(COMPOSE + ["exec", "-T", node, "clickhouse-client", "--config-file", ADMIN_CONFIG,
                                  "--multiquery"], input=query, capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(podman_noise_removed(r.stderr)[:300])
    return r.stdout.strip()


def try_sql(node, query, timeout=30):
    try:
        return sql(node, query, timeout)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        return f"error: {str(e).splitlines()[0] if str(e) else 'timeout'}"


def keeper_role(node):
    """This node's Keeper state (leader/follower), from the mntr four-letter command."""
    rc, out, _ = sh(node, "exec 3<>/dev/tcp/127.0.0.1/9181 && printf mntr >&3 && timeout 3 cat <&3", timeout=10)
    m = re.search(r"zk_server_state\s+(\w+)", out)
    return m.group(1) if m else "unreachable"


def snapshot():
    return {n: (try_sql(n, "SELECT version()"), keeper_role(n)) for n in NODES}


class Writer(threading.Thread):
    """Inserts a row into citizenlab every half second, on each node in turn, and keeps the
    urls whose insert succeeded, and the errors of those that didn't."""
    def __init__(self):
        super().__init__(daemon=True)
        self.ok, self.errors, self.stop, self.i = [], [], threading.Event(), 0

    def run(self):
        nodes = list(NODES)
        while not self.stop.is_set():
            node = nodes[self.i % len(nodes)]
            url = f"https://example.org/w{self.i}"
            r = try_sql(node, f"INSERT INTO ooni.citizenlab VALUES ('example.org', '{url}', 'ZZ', 'TEST')")
            (self.errors.append((node, r)) if r.startswith("error") else self.ok.append(url))
            self.i += 1
            time.sleep(0.5)

    def take(self):
        ok, errors = len(self.ok), list(self.errors)
        self.errors.clear()
        return ok, errors


def report(title, writer=None, ok_before=0):
    print(f"\n--- {title}")
    for n, (version, keeper) in snapshot().items():
        print(f"    {n}: ClickHouse {version}, Keeper {keeper}")
    if writer:
        ok, errors = writer.take()
        print(f"    inserts: {ok - ok_before} succeeded, {len(errors)} failed")
        for node, e in errors[:5]:
            print(f"      {node}: {e[:160]}")
        return ok
    return ok_before


# --- the test ------------------------------------------------------------------------------

def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(os.path.join(TESTS, "cache/debs"), exist_ok=True)
    write_inventory()
    prod = yaml.safe_load(open(os.path.join(INV, "group_vars/clickhouse.yml")))["clickhouse_version"]
    from_version = os.environ.get("FROM_VERSION") or prod
    to_version = os.environ.get("TO_VERSION") or next_version()
    print(f"upgrading {from_version} -> {to_version}")
    if from_version == to_version:
        sys.exit(f"nothing to upgrade: FROM_VERSION and TO_VERSION are both {from_version}; "
                 "move next_version on")

    set_version(from_version)
    r = compose("up", "-d", "--build", "--quiet-pull")
    check(r.returncode == 0, "the three hosts start")
    if r.returncode:
        sys.exit(r.stderr[-2000:])
    for n in NODES:
        # "degraded" is normal in a container (e.g. kernel mounts it can't have)
        rc, state, _ = sh(n, "systemctl is-system-running --wait", timeout=120)
        check(state in ("running", "degraded"), f"{n} boots with systemd ({state})")
        # what the role's upstream version left on production's hosts: the repository
        # without signed-by, and its key among apt's trusted keys (it used apt-key)
        compose("cp", os.path.join(TESTS, "../../files/clickhouse-repo-keyring.asc"), f"{n}:/etc/apt/trusted.gpg.d/clickhouse.asc")
        sh(n, "echo 'deb https://packages.clickhouse.com/deb lts main' > /etc/apt/sources.list.d/packages_clickhouse_com_deb.list")
    # A new cluster: the hosts one at a time, then the ooni database once Keeper has a quorum
    rc, took = deploy("from", args=["--skip-tags", "clickhouse_schema"])
    check(rc == 0, f"the role deploys {from_version} to the three hosts, one at a time ({took:.0f}s)")
    rc2, _ = deploy("schema", args=["--tags", "clickhouse_schema"])
    check(rc2 == 0, "the schema step creates the ooni database on the three hosts")
    if rc or rc2:
        sys.exit(1)
    for n in NODES:
        check(try_sql(n, "SELECT version()") == from_version, f"{n} runs {from_version}")
    sql("data1", "INSERT INTO ooni.citizenlab VALUES ('example.org', 'https://example.org/before', 'ZZ', 'TEST')")
    report("before the upgrade")

    writer = Writer()
    writer.start()
    ok_so_far = 0
    set_version(to_version)
    for i, (n, host) in enumerate(NODES.items(), 1):
        rc, took = deploy(f"to-{n}", limit=host)
        check(rc == 0, f"step {i}: the role upgrades {n} and finds it running {to_version} ({took:.0f}s)")
        check(try_sql(n, "SELECT version()") == to_version, f"step {i}: {n} runs {to_version}")
        rc, active, _ = sh(n, "systemctl is-active clickhouse-server")
        check(active == "active", f"step {i}: clickhouse-server is active under systemd on {n}")
        rc, pin, _ = sh(n, "grep '^Pin:' /etc/apt/preferences.d/clickhouse; dpkg-query -W -f '${Version}' clickhouse-server")
        check(f"Pin: version {to_version}" in pin and pin.endswith(to_version), f"step {i}: {n}'s packages are {to_version}, pinned")
        for other in NODES:
            check(wait_keeper(other), f"step {i}: {other} answers and reaches Keeper")
        ok_so_far = report(f"after step {i} ({n} upgraded)", writer, ok_so_far)
    time.sleep(5)
    writer.stop.set()
    writer.join()
    report("after the upgrade", writer, ok_so_far)

    check(len(writer.ok) > 20, f"inserts kept working during the rollout ({len(writer.ok)} succeeded)")
    for n in NODES:  # after the rollout, every node takes inserts
        url = f"https://example.org/after-{n}"
        check(not try_sql(n, f"INSERT INTO ooni.citizenlab VALUES ('example.org', '{url}', 'ZZ', 'TEST')").startswith("error"),
              f"{n} takes inserts after the upgrade")
        writer.ok.append(url)
    for n in NODES:
        check(try_sql(n, "SELECT version()") == to_version, f"{n} runs {to_version}")
        sql(n, "SYSTEM SYNC REPLICA ooni.citizenlab", timeout=300)
        bad = sql(n, "SELECT count() FROM system.replicas WHERE is_readonly OR is_session_expired")
        check(bad == "0", f"{n} has no read-only replicated tables")
        stuck = sql(n, "SELECT count() FROM system.replication_queue WHERE num_tries > 10")
        check(stuck == "0", f"{n} has no replication tasks failing over and over")
        urls = set(sql(n, "SELECT url FROM ooni.citizenlab FINAL").split())
        check("https://example.org/before" in urls, f"{n} has the row inserted before the upgrade")
        missing = [u for u in writer.ok if u not in urls]
        check(not missing, f"{n} has all {len(writer.ok)} rows whose insert succeeded (missing: {missing[:3]})")

    print(f"\n{len(failures)} failed" if failures else "\nall passed")
    sys.exit(1 if failures else 0)


def next_version():
    lines = [l.strip() for l in open(os.path.join(TESTS, "next_version")) if l.strip() and not l.startswith("#")]
    return lines[0]


def wait_keeper(node, seconds=60):
    """Whether node answers and reaches Keeper within `seconds` (a Keeper election may be
    under way after a restart)."""
    for _ in range(seconds // 2):
        if try_sql(node, "SELECT count() FROM system.zookeeper WHERE path = '/'").isdigit():
            return True
        time.sleep(2)
    return False


def compose(*args):
    return subprocess.run(COMPOSE + list(args), capture_output=True, text=True)


if __name__ == "__main__":
    main()
