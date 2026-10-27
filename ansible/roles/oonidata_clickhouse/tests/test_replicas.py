#!/usr/bin/env python3
"""
Adds a replica to the cluster and removes it again, the way an operator would: by editing
the cluster in vars and rerunning the roles. Uses the real ansible/group_vars and host_vars
(secrets replaced by test values) and the clickhouse role's rendered configs, with one
container per production host (compose.yml), and checks that:

- data1-3 form the Keeper ensemble and oonidata_cluster, and oonidata_clickhouse's schema
  step creates the ooni database from schema.sql on each, but not on a non-member host;
- after data4 is added to clickhouse_remote_servers and clickhouse_macros, every node
  sees four replicas, the schema step creates the database on data4 alone, data4's
  replicated tables catch up, and ON CLUSTER DDL and inserts reach it;
- after data4 is removed from vars and from Keeper (SYSTEM DROP REPLICA), every node sees
  three replicas, Keeper has no trace of it, ON CLUSTER DDL doesn't wait for it, and
  data1-3 still replicate;
- a re-imaged data4 (empty disk, same replica name) can be added again.

Called by run.sh; needs ansible-playbook and PyYAML.
"""
import os, re, shutil, subprocess, sys, time
import yaml

TESTS = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.normpath(os.path.join(TESTS, "../../.."))
REPO = os.path.dirname(ANSIBLE)
SCHEMA = os.path.join(REPO, "scripts/cluster-migration/schema.sql")
OUT = os.path.join(TESTS, "out")
INV = os.path.join(OUT, "inventory")
COMPOSE = os.environ.get("COMPOSE", "docker compose").split() + ["-f", os.path.join(TESTS, "compose.yml")]
HOSTS = {f"data{i}": f"data{i}.htz-fsn.prod.ooni.nu" for i in (1, 2, 3, 4)}
NON_MEMBER = "notebook1.htz-fsn.prod.ooni.nu"  # in [clickhouse], as in production, but not a replica
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


def secrets_replaced(text):
    return re.sub(r"lookup\('amazon\.aws\.aws_(?:ssm|secret)', '([^']+)'[^)]*\)",
                  lambda m: "'test-" + m.group(1).rsplit("/", 1)[-1] + "'", text)


# --- the inventory: production's vars, and a cluster that the test edits -----------------

def write_inventory():
    shutil.rmtree(INV, ignore_errors=True)
    os.makedirs(os.path.join(INV, "group_vars"))
    os.makedirs(os.path.join(INV, "host_vars"))
    for src, dst in (("group_vars/all/vars.yml", "group_vars/all.yml"),
                     ("group_vars/clickhouse/vars.yml", "group_vars/clickhouse.yml")):
        open(os.path.join(INV, dst), "w").write(secrets_replaced(open(os.path.join(ANSIBLE, src)).read()))
    for host in list(HOSTS.values()) + [NON_MEMBER]:
        src = os.path.join(ANSIBLE, "host_vars", host)
        if os.path.isfile(src):
            open(os.path.join(INV, "host_vars", host + ".yml"), "w").write(secrets_replaced(open(src).read()))
    return yaml.safe_load(open(os.path.join(INV, "group_vars/clickhouse.yml")))


def set_cluster(nodes):
    """The cluster in vars as an operator edits it: a replica in oonidata_cluster and a
    replica macro for each node (data1-3 keep production's entries)."""
    v = dict(VARS)
    replicas = [{"replica": None, "host": f"clickhouse{n[-1]}.prod.ooni.io", "port": 9000} for n in nodes]
    server = dict(v["clickhouse_remote_servers"][0])
    server["shards"] = [dict(server["shards"][0], replicas=replicas)]
    v["clickhouse_remote_servers"] = [server]
    macros = [m for m in VARS["clickhouse_macros"] if "server" not in m or m["server"][0] in [HOSTS[n] for n in nodes]]
    if "data4" in nodes:
        macros.insert(-1, {"macro": "<shard>01</shard>\n<replica>04</replica>\n", "server": [HOSTS["data4"]]})
    v["clickhouse_macros"] = macros
    yaml.safe_dump(v, open(os.path.join(INV, "group_vars/clickhouse.yml"), "w"), sort_keys=False)
    open(os.path.join(INV, "hosts.ini"), "w").write(
        "[clickhouse]\n" + "\n".join([HOSTS[n] for n in nodes] + [NON_MEMBER]) + "\n")


def ansible(playbook, limit=None):
    cmd = ["ansible-playbook", "-i", os.path.join(INV, "hosts.ini"), os.path.join(TESTS, playbook)]
    if limit:
        cmd += ["--limit", limit]
    env = dict(os.environ, ANSIBLE_ROLES_PATH=os.path.join(ANSIBLE, "roles"), TESTS=TESTS, SCHEMA=SCHEMA,
               ANSIBLE_NOCOLOR="1", ANSIBLE_PYTHON_INTERPRETER=sys.executable,
               COMPOSE=" ".join(COMPOSE[:-2]))
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    open(os.path.join(OUT, f"ansible-{playbook}-{time.strftime('%H%M%S')}.log"), "w").write(r.stdout + r.stderr)
    if r.returncode:
        print(r.stdout[-3000:] + r.stderr[-2000:])
    return r.returncode, r.stdout


def status(stdout, task, host):
    """What `task` reported for `host` in ansible's output: ok, changed, skipping or None."""
    m = re.search(r"TASK \[[^\]]*" + re.escape(task) + r"\][^\n]*\n(.*?)(?=\nTASK |\nPLAY RECAP)", stdout, re.S)
    s = m and re.search(r"^(ok|changed|skipping|fatal): \[" + re.escape(host) + r"\]", m.group(1), re.M)
    return s.group(1) if s else None


def changed(stdout, task, host):
    return status(stdout, task, host) == "changed"


# --- the containers ----------------------------------------------------------------------

def compose(*args):
    return subprocess.run(COMPOSE + list(args), capture_output=True, text=True)


def sql(node, query, timeout=60):
    r = subprocess.run(COMPOSE + ["exec", "-T", node, "clickhouse-client", "-u", ADMIN_USER, "--password",
                                  ADMIN_PASSWORD, "--multiquery"], input=query, capture_output=True, text=True,
                       timeout=timeout)
    if r.returncode:
        error = "\n".join(l for l in r.stderr.splitlines() if not l.startswith("Emulate Docker CLI"))
        raise RuntimeError(f"{node}: {error.strip()[:500]}")
    return r.stdout.strip()


def wait_ready(node):
    for _ in range(120):
        try:
            if sql(node, "SELECT count() FROM system.zookeeper WHERE path = '/'") != "":
                return True
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(1)
    return False


def keeper_role(node):
    """This node's Keeper state (leader/follower), from the mntr four-letter command."""
    r = subprocess.run(COMPOSE + ["exec", "-T", node, "bash", "-c",
                                  "exec 3<>/dev/tcp/127.0.0.1/9181 && printf mntr >&3 && timeout 3 cat <&3"],
                       capture_output=True, text=True, timeout=15)
    m = re.search(r"zk_server_state\s+(\w+)", r.stdout)
    return m.group(1) if m else "unreachable"


def restart_one_at_a_time(nodes):
    """What a deploy with serial: 1 does after a config change: restart each node and wait
    until it's back, its own Keeper too, before the next; then check that inserts work."""
    for n in nodes:
        compose("restart", n)
        check(wait_ready(n), f"{n} is back after its restart")
        keeper = None
        for _ in range(60):
            keeper = keeper_role(n)
            if keeper in ("leader", "follower"):
                break
            time.sleep(1)
        check(keeper in ("leader", "follower"), f"{n}'s Keeper is back in the ensemble ({keeper})")
        insert([o for o in nodes if o != n][0], f"after-{n}-restart")


def replicas_in_cluster(node):
    return sql(node, "SELECT host_name FROM system.clusters WHERE cluster = 'oonidata_cluster' ORDER BY replica_num FORMAT TSV").split()


def insert(node, tag):
    sql(node, f"INSERT INTO ooni.citizenlab VALUES ('example.org', 'https://example.org/{tag}', 'ZZ', 'TEST')")


def citizenlab(node):
    sql(node, "SYSTEM SYNC REPLICA ooni.citizenlab", timeout=120)
    return sql(node, "SELECT groupArray(url) FROM (SELECT url FROM ooni.citizenlab FINAL ORDER BY url)")


def replicated_tables(node):
    return sql(node, "SELECT table FROM system.replicas WHERE database = 'ooni' ORDER BY table FORMAT TSV").split()


def keeper_replicas(node):
    """Replica names under each replicated table's Keeper path, as seen from node."""
    out = {}
    for line in sql(node, "SELECT table, zookeeper_path FROM system.replicas WHERE database = 'ooni' FORMAT TSV").splitlines():
        table, path = line.split("\t")
        out[table] = sql(node, f"SELECT groupArray(name) FROM (SELECT name FROM system.zookeeper WHERE path = '{path}/replicas' ORDER BY name)")
    return out


def schema_objects():
    return len(re.findall(r"^CREATE (?:TABLE|MATERIALIZED VIEW) IF NOT EXISTS", open(SCHEMA).read(), re.M))


def on_cluster_ddl(node, name):
    sql(node, f"SET distributed_ddl_task_timeout = 60; "
              f"CREATE TABLE ooni.{name} ON CLUSTER oonidata_cluster (x UInt8) ENGINE = Memory")


# --- the test ----------------------------------------------------------------------------

def main():
    global VARS, ADMIN_USER, ADMIN_PASSWORD
    os.makedirs(OUT, exist_ok=True)
    VARS = write_inventory()
    ADMIN_USER = VARS["clickhouse_admin_user"]
    ADMIN_PASSWORD = re.fullmatch(r"\{\{ '([^']+)' \}\}", VARS["clickhouse_admin_password"]).group(1)
    three = ["data1", "data2", "data3"]

    # A three-node cluster from production's vars
    set_cluster(three)
    check(ansible("render.yml")[0] == 0, "the clickhouse role renders config.xml and users.xml for data1-3")
    compose("up", "-d", "--quiet-pull", *three)
    check(all(wait_ready(n) for n in three), "data1-3 start and reach Keeper")
    rc, out = ansible("schema.yml")
    check(rc == 0, "the schema step runs on data1-3")
    check(all(changed(out, "Create the tables and views of schema.sql", HOSTS[n]) for n in three),
          "the schema step creates the ooni database on data1-3")
    check(status(out, "Check whether the ooni database exists", NON_MEMBER) == "skipping",
          "the schema step skips a host that isn't in the cluster")
    n_objects = schema_objects()
    for n in three:
        count = int(sql(n, "SELECT count() FROM system.tables WHERE database = 'ooni'"))
        check(count == n_objects, f"{n} has the {n_objects} tables and views of schema.sql ({count})")
    rc, out = ansible("schema.yml")
    check(rc == 0 and all(status(out, "Create the ooni database", HOSTS[n]) == "skipping" for n in three),
          "a second run leaves the existing databases alone")
    insert("data1", "before")
    check(len({citizenlab(n) for n in three}) == 1, "data1-3 replicate citizenlab")

    # Add data4: edit the cluster in vars, render, restart one at a time, start data4
    set_cluster(three + ["data4"])
    check(ansible("render.yml")[0] == 0, "the clickhouse role renders the configs with data4")
    restart_one_at_a_time(three)
    compose("up", "-d", "--quiet-pull", "data4")
    check(wait_ready("data4"), "data4 starts and reaches Keeper")
    for n in three + ["data4"]:
        check(replicas_in_cluster(n) == [f"clickhouse{i}.prod.ooni.io" for i in (1, 2, 3, 4)],
              f"{n} sees four replicas in oonidata_cluster")
    rc, out = ansible("schema.yml")
    check(rc == 0 and changed(out, "Create the tables and views of schema.sql", HOSTS["data4"])
          and all(status(out, "Create the ooni database", HOSTS[n]) == "skipping" for n in three),
          "the schema step creates the ooni database on data4 alone")
    check(replicated_tables("data4") == replicated_tables("data1"), "data4 has every replicated table")
    check(all("'04'" in names for names in keeper_replicas("data1").values()),
          "Keeper lists replica 04 for every replicated table")
    check(citizenlab("data4") == citizenlab("data1"), "data4 catches up on citizenlab")
    insert("data4", "from-data4")
    check(len({citizenlab(n) for n in three + ["data4"]}) == 1, "an insert on data4 reaches data1-3")
    on_cluster_ddl("data1", "ddl_with_four")
    check(all(sql(n, "EXISTS TABLE ooni.ddl_with_four") == "1" for n in three + ["data4"]),
          "ON CLUSTER DDL reaches data4")

    # Remove data4: edit vars back, render, restart one at a time, stop data4, drop its replica
    set_cluster(three)
    check(ansible("render.yml")[0] == 0, "the clickhouse role renders the configs without data4")
    restart_one_at_a_time(three)
    compose("stop", "data4")
    sql("data1", "SYSTEM DROP REPLICA '04'")
    for n in three:
        check(replicas_in_cluster(n) == [f"clickhouse{i}.prod.ooni.io" for i in (1, 2, 3)],
              f"{n} sees three replicas in oonidata_cluster")
    check(all("'04'" not in names for names in keeper_replicas("data1").values()),
          "Keeper has no replica 04 left")
    start = time.time()
    on_cluster_ddl("data1", "ddl_with_three")
    check(time.time() - start < 30 and all(sql(n, "EXISTS TABLE ooni.ddl_with_three") == "1" for n in three),
          "ON CLUSTER DDL completes without data4")
    insert("data2", "after-removal")
    check(len({citizenlab(n) for n in three}) == 1, "data1-3 still replicate")

    # Re-image data4 (empty disk, same replica name) and add it again
    compose("rm", "-f", "-s", "-v", "data4")
    set_cluster(three + ["data4"])
    check(ansible("render.yml")[0] == 0, "the configs with data4 are rendered again")
    restart_one_at_a_time(three)
    compose("up", "-d", "data4")
    check(wait_ready("data4"), "the re-imaged data4 starts")
    rc, out = ansible("schema.yml", limit=HOSTS["data4"])
    check(rc == 0 and changed(out, "Create the tables and views of schema.sql", HOSTS["data4"]),
          "the schema step creates the ooni database on the re-imaged data4")
    check(citizenlab("data4") == citizenlab("data1"), "the re-imaged data4 catches up")

    print(f"\n{len(failures)} failed" if failures else "\nall passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
