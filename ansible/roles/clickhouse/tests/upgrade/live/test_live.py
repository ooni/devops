#!/usr/bin/env python3
"""
The production upgrade, rehearsed on a sample of real data: three Debian hosts named like
data1-3 (compose.yml) go from what main deploys today to this branch's clickhouse_version,
the way it will be done in production.

0. FROM: ClickHouse as main deploys it (FROM_REF: its galaxy role and vars, secrets replaced
   by test values), the ooni database as production has it (SCHEMA_REF's schema.sql), and a
   window of real measurements copied from another ClickHouse (SAMPLE_CLIENT), with some
   rows inserted twice, as reprocessing does.
A. This branch's role at FROM's version, one host at a time (--limit, in ORDER): the role
   change alone.
B. This branch's clickhouse_version, one host at a time: the version hop.

During A and B a writer inserts into fastpath as the fastpath user and a reader runs an API
query as oonimeasurements, each on every node in turn. After 0, A and B it records, per
node: the server version, its config files, its users, roles, quotas, settings profiles and
grants, the settings each user gets, which users can log in, every table's definition and
its content (a checksum of each row, after FINAL where the engine merges rows), the results
of the API-shaped queries in queries.sql, system.warnings and the server's errors. It fails
if the content or a query result changes, if a node differs from the others, if a user can
no longer log in, or if a deploy fails; everything else that changed is listed in
out/report.md for a person to judge.

    ./run.sh                       # KEEP=1 leaves the hosts running
"""
import calendar, difflib, hashlib, json, os, re, shutil, subprocess, sys, threading, time
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
UPGRADE = os.path.dirname(HERE)
ANSIBLE = os.path.normpath(os.path.join(HERE, "../../../../.."))
REPO = os.path.dirname(ANSIBLE)
OUT = os.path.join(HERE, "out")
CACHE = os.path.join(HERE, "cache")
COMPOSE = os.environ.get("COMPOSE", "docker compose").split() + ["-f", os.path.join(HERE, "compose.yml")]
NODES = {"data1": "data1.htz-fsn.prod.ooni.nu", "data2": "data2.htz-fsn.prod.ooni.nu",
         "data3": "data3.htz-fsn.prod.ooni.nu"}
ORDER = os.environ.get("ORDER", "data3 data2 data1").split()
FROM_REF = os.environ.get("FROM_REF", "origin/main")
SCHEMA_REF = os.environ.get("SCHEMA_REF", "d5ffb094")  # #521: schema.sql as production has it, 2026-11-09
SAMPLE_CLIENT = os.environ.get("SAMPLE_CLIENT", "podman exec -i realdata-ch clickhouse-client").split()
WINDOW = os.environ.get("SAMPLE_WINDOW", "2026-09-30 22:00:00/2026-10-01 02:00:00").split("/")
ADMIN = ["-u", "admin", "--password", "test-clickhouse_admin_password"]
# What each user's password is with the secrets replaced (secrets_replaced below)
USERS = {"admin": "test-clickhouse_admin_password", "default": "", "readonly": "test-clickhouse_readonly_password",
         "write": "test-clickhouse_write_password", "fastpath": "test-clickhouse_fastpath_password",
         "oonimeasurements": "test-clickhouse_oonimeasurements_password",
         "ooniprobe": "test-clickhouse_ooniprobe_password", "oonirun": "test-clickhouse_oonirun_password",
         "oonitestlists": "test-clickhouse_oonitestlists_password", "notebook": "test-clickhouse_notebook_password"}
SEEDS = os.path.join(ANSIBLE, "roles/clickhouse/tests/seed")
# Rows the test itself writes, left out of the content checks
OWN_ROWS = {"fastpath": "measurement_uid NOT LIKE 'upgradetest-%'"}
failures, notes = [], []


def log(msg):
    print(msg, flush=True)


def check(ok, what):
    log(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)
    return ok


def run(cmd, timeout=600, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def compose(*args, timeout=600):
    return run(COMPOSE + list(args), timeout=timeout)


def quiet(stderr):
    noise = ("Emulate Docker CLI", "Executing external compose provider", "Error: executing ")
    return "\n".join(l for l in stderr.splitlines() if not any(n in l for n in noise) and l.strip("\x1b[0m ")).strip()


def sh(node, command, timeout=120):
    r = run(["docker", "exec", f"chlive-{node}", "bash", "-c", command], timeout=timeout)
    return r.returncode, r.stdout.strip(), quiet(r.stderr)


def sql(node, query, user=ADMIN, timeout=300):
    cmd = ["docker", "exec", "-i", f"chlive-{node}", "clickhouse-client", *user, "--multiquery"]
    r = run(cmd, input=query, timeout=timeout)
    if r.returncode:
        raise RuntimeError(quiet(r.stderr)[:400] or f"exit {r.returncode}")
    return r.stdout.rstrip("\n")


def try_sql(node, query, user=ADMIN, timeout=30):
    try:
        return sql(node, query, user, timeout)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        return "error: " + (str(e).splitlines()[0] if str(e) else "timeout")


def as_user(name):
    return ["-u", name] + (["--password", USERS[name]] if USERS[name] else [])


# --- inventories ---------------------------------------------------------------------------

def secrets_replaced(text):
    return re.sub(r"lookup\('amazon\.aws\.aws_(?:ssm|secret)', '([^']+)'[^)]*\)",
                  lambda m: "'test-" + m.group(1).rsplit("/", 1)[-1] + "'", text)


def write_inventory(inv, ansible_dir):
    shutil.rmtree(inv, ignore_errors=True)
    os.makedirs(os.path.join(inv, "group_vars"))
    os.makedirs(os.path.join(inv, "host_vars"))
    for src, dst in (("group_vars/all/vars.yml", "group_vars/all.yml"),
                     ("group_vars/clickhouse/vars.yml", "group_vars/clickhouse.yml")):
        open(os.path.join(inv, dst), "w").write(secrets_replaced(open(os.path.join(ansible_dir, src)).read()))
    for node, host in NODES.items():
        src = os.path.join(ansible_dir, "host_vars", host)
        text = secrets_replaced(open(src).read()) if os.path.isfile(src) else ""
        text += f"\nansible_connection: community.docker.docker\nansible_host: chlive-{node}\n"
        open(os.path.join(inv, "host_vars", host + ".yml"), "w").write(text)
    open(os.path.join(inv, "hosts.ini"), "w").write("[clickhouse]\n" + "\n".join(NODES.values()) + "\n")


def version_in(inv):
    return yaml.safe_load(open(os.path.join(inv, "group_vars/clickhouse.yml")))["clickhouse_version"]


def set_version(inv, version):
    p = os.path.join(inv, "group_vars/clickhouse.yml")
    text, n = re.subn(r"^clickhouse_version: .*$", f"clickhouse_version: {version}", open(p).read(), flags=re.M)
    assert n == 1
    open(p, "w").write(text)


def prepare_from():
    """main's ansible directory, and the galaxy clickhouse role its requirements pin"""
    src = os.path.join(OUT, "from")
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    archive = subprocess.run(["git", "-C", REPO, "archive", FROM_REF, "ansible"], capture_output=True, check=True)
    subprocess.run(["tar", "-x", "-C", src], input=archive.stdout, check=True)
    reqs = yaml.safe_load(open(os.path.join(src, "ansible/requirements/ansible-galaxy.yml")))
    role = next(r for r in reqs["roles"] if r.get("name") == "idealista.clickhouse_role")
    roles = os.path.join(CACHE, f"roles-{role['version']}")
    if not os.path.isdir(os.path.join(roles, "idealista.clickhouse_role")):
        r = run(["ansible-galaxy", "role", "install", "-p", roles,
                 f"git+{role['src']},{role['version']},idealista.clickhouse_role"])
        assert r.returncode == 0, r.stdout + r.stderr
    open(os.path.join(OUT, "from-deploy.yml"), "w").write(
        "# What main's deploy-clickhouse.yml does to a replica, without nftables\n"
        "- hosts: clickhouse\n  gather_facts: true\n  roles: [idealista.clickhouse_role]\n")
    return os.path.join(src, "ansible"), roles, role["version"]


def deploy(label, inv, playbook, roles_path, limit=None, args=()):
    hosts = [n for n, h in NODES.items() if limit in (None, h)]
    for n in hosts:  # packages downloaded by earlier hosts
        sh(n, "cp -n /debs/*.deb /var/cache/apt/archives/ 2>/dev/null; true")
    cmd = ["ansible-playbook", "-i", os.path.join(inv, "hosts.ini"), playbook, *args]
    if limit:
        cmd += ["--limit", limit]
    env = dict(os.environ, ANSIBLE_ROLES_PATH=roles_path, ANSIBLE_NOCOLOR="1",
               SCHEMA=os.path.join(REPO, "scripts/cluster-migration/schema.sql"))
    started = time.time()
    r = run(cmd, env=env, timeout=1800)
    open(os.path.join(OUT, f"ansible-{label}.log"), "w").write(r.stdout + r.stderr)
    for n in hosts:
        sh(n, "cp -n /var/cache/apt/archives/*.deb /debs/ 2>/dev/null; true")
    recap = re.findall(r"^(\S+)\s+: ok=(\d+)\s+changed=(\d+).*failed=(\d+)", r.stdout, re.M)
    if r.returncode:
        log(r.stdout[-3000:] + r.stderr[-1500:])
    return r.returncode, time.time() - started, recap, changed_tasks(r.stdout)


def changed_tasks(stdout):
    """The tasks that reported changed, from ansible's default output"""
    out, task = [], None
    for line in stdout.splitlines():
        m = re.match(r"^(?:TASK|RUNNING HANDLER) \[(.*)\]", line)
        if m:
            task = m.group(1)
        elif line.startswith("changed:") and task:
            out.append(task)
    return out


# --- production's SQL users ----------------------------------------------------------------

def apply_seeds():
    """Production's SQL users, roles, quotas and grants as the role's tests record them
    (tests/seed/<node>.sql, from 2026-10-26): made by hand and drifted from vars, not the ones
    main's role just created from vars. Its SQL objects are dropped and the seed's created."""
    sha = lambda x: hashlib.sha256(x.encode()).hexdigest()
    for n in NODES:
        text = open(os.path.join(SEEDS, f"{n}.sql")).read()
        text = re.sub(r"\{password:(\w+)\}", lambda m: sha(USERS[m.group(1)]), text)
        text = re.sub(r"\{old_password:(\w+)\}", lambda m: sha("old-" + m.group(1)), text)
        drops = []
        for kind, what in (("users", "USER"), ("roles", "ROLE"), ("quotas", "QUOTA")):
            for name in sql(n, f"SELECT name FROM system.{kind} WHERE storage = 'local_directory' FORMAT TSV").split():
                drops.append(f"DROP {what} IF EXISTS `{name}`;")
        sql(n, "\n".join(drops) + "\n" + text)
        notes.append(f"0: {n}'s SQL users, roles, quotas and grants are tests/seed/{n}.sql's")


# --- data ----------------------------------------------------------------------------------

def columns(client, table, insertable=False):
    q = (f"SELECT name FROM system.columns WHERE database = 'ooni' AND table = '{table}'"
         + (" AND default_kind NOT IN ('MATERIALIZED', 'ALIAS', 'EPHEMERAL')" if insertable else "")
         + " ORDER BY position FORMAT TSV")
    return client(q).split()


def load_sample():
    src = lambda q: run(SAMPLE_CLIENT + ["--max_threads", "4", "--max_memory_usage", "4000000000", "-q", q],
                        timeout=900).stdout
    a, b = WINDOW
    mid = "2026-10-01 00:00:00"
    timed = ["fastpath", "obs_web", "obs_web_ctrl", "analysis_web_measurement", "obs_http_middlebox"]
    whole = ["citizenlab", "fingerprints_dns", "fingerprints_http", "test_groups", "url_priorities",
             "asnmeta", "event_detector_changepoints", "msmt_feedback", "faulty_measurements"]
    loaded = {}

    def copy(table, where, node="data1", limit=""):
        theirs = set(columns(src, table))
        mine = columns(lambda q: sql(node, q), table, insertable=True)
        cols = [c for c in mine if c in theirs]
        if not cols:
            return 0
        clist = ", ".join(f"`{c}`" for c in cols)
        p1 = subprocess.Popen(SAMPLE_CLIENT + ["--max_threads", "4", "--max_memory_usage", "4000000000", "-q",
                              f"SELECT {clist} FROM ooni.{table} {where} {limit} FORMAT Native"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.run(["docker", "exec", "-i", f"chlive-{node}", "clickhouse-client", *ADMIN,
                             "--max_insert_block_size", "200000",
                             "-q", f"INSERT INTO ooni.{table} ({clist}) FORMAT Native"],
                            stdin=p1.stdout, capture_output=True, timeout=1800)
        p1.wait()
        if b"NO_DATA_TO_INSERT" in p2.stderr:  # empty in the source
            notes.append(f"sample: {table}: no rows in the source{' (' + node + ')' if node != 'data1' else ''}")
            return 0
        if p2.returncode or p1.returncode:
            raise RuntimeError(f"{table}: {p1.stderr.read().decode()[:300]} {p2.stderr.decode()[:300]}")
        missing = [c for c in mine if c not in theirs]
        if missing:
            notes.append(f"sample: {table}: columns not in the source, left to their defaults: {', '.join(missing)}")
        return len(cols)

    have = set(src("SELECT name FROM system.tables WHERE database = 'ooni' FORMAT TSV").split())
    for t in timed:
        if t in have:
            # two inserts, either side of a month boundary: several parts, two partitions
            copy(t, f"WHERE measurement_start_time >= '{a}' AND measurement_start_time < '{mid}'")
            copy(t, f"WHERE measurement_start_time >= '{mid}' AND measurement_start_time < '{b}'")
    for t in whole:
        if t in have and t in set(sql("data1", "SELECT name FROM system.tables WHERE database = 'ooni' FORMAT TSV").split()):
            copy(t, "")
            if t.startswith("fingerprints_"):  # not replicated: on data1 and data2, as in production
                copy(t, "", node="data2")
    if "jsonl" in have:  # the rows of the sampled measurements
        copy("jsonl", f"WHERE (report_id, input) IN (SELECT report_id, input FROM ooni.fastpath "
                      f"WHERE measurement_start_time >= '{a}' AND measurement_start_time < '{b}')")
    # Copies of some rows, inserted again on another node, as reprocessing does
    copy("fastpath", f"WHERE measurement_start_time >= '{mid}' AND measurement_start_time < '{b}'",
         node="data2", limit="ORDER BY measurement_uid LIMIT 5000")
    copy("obs_web", f"WHERE measurement_start_time >= '{a}' AND measurement_start_time < '{mid}'",
         node="data3", limit="ORDER BY measurement_uid, observation_idx LIMIT 20000")
    for n in NODES:
        sync(n)
    return {t: sql("data1", f"SELECT count() FROM ooni.`{t}`") for t in tables("data1")}


def tables(node):
    return sql(node, "SELECT name FROM system.tables WHERE database = 'ooni' AND NOT startsWith(name, '.inner') "
                     "AND engine NOT IN ('MaterializedView', 'View') ORDER BY name FORMAT TSV").split()


def sync(node):
    for t in sql(node, "SELECT table FROM system.replicas WHERE database = 'ooni' FORMAT TSV").split():
        sql(node, f"SYSTEM SYNC REPLICA ooni.`{t}`", timeout=900)


# --- snapshots -----------------------------------------------------------------------------

def content(node):
    """{table: 'rows checksum'} over each table's rows as queries see them (FINAL for engines
    that merge rows), minus the test's own rows"""
    out = {}
    engines = dict(l.split("\t") for l in sql(node, "SELECT name, engine FROM system.tables WHERE database = 'ooni' "
                                                    "FORMAT TSV").splitlines())
    for t in tables(node):
        final = " FINAL" if re.search(r"Replacing|Collapsing|Summing|Aggregating", engines[t]) else ""
        where = f" WHERE {OWN_ROWS[t]}" if t in OWN_ROWS else ""
        # capped: 24.8 doesn't see the container's memory limit and would size itself to the host's
        out[t] = sql(node, f"SELECT count(), sum(cityHash64(formatRow('RowBinary', *))) FROM ooni.`{t}`{final}{where} "
                           f"SETTINGS max_memory_usage = 1500000000, max_threads = 2", timeout=900).replace("\t", " ")
    return out


def snapshot(label):
    d = os.path.join(OUT, "snap", label)
    shutil.rmtree(d, ignore_errors=True)
    snap = {}
    for n in NODES:
        nd = os.path.join(d, n)
        os.makedirs(nd)
        s = snap[n] = {}
        s["version"] = try_sql(n, "SELECT version()")
        # config files, as text
        rc, files, _ = sh(n, "find /etc/clickhouse-server /etc/clickhouse-client /etc/systemd/system "
                             "/lib/systemd/system/clickhouse-server.service /etc/apt/sources.list.d "
                             "/etc/apt/preferences.d -type f 2>/dev/null | grep -i -e clickhouse -e sources.list.d "
                             "-e preferences.d | sort")
        s["files"] = {}
        for f in files.split():
            rc, text, _ = sh(n, f"cat {f}")
            s["files"][f] = text
        s["unit"] = sh(n, "systemctl cat clickhouse-server 2>/dev/null")[1]
        s["packages"] = sh(n, "dpkg-query -W 'clickhouse*'")[1]
        s["logins"] = {u: try_sql(n, "SELECT currentUser()", as_user(u)) for u in USERS}
        s["settings"] = {u: try_sql(n, "SELECT name, value FROM system.settings WHERE changed ORDER BY name "
                                       "FORMAT TSV", as_user(u)) for u in USERS}
        s["server_settings"] = try_sql(n, "SELECT name, value FROM system.server_settings WHERE changed "
                                          "ORDER BY name FORMAT TSV")
        acl = []
        for kind, show in (("users", "USER"), ("roles", "ROLE"), ("quotas", "QUOTA"),
                           ("settings_profiles", "SETTINGS PROFILE"), ("row_policies", "ROW POLICY")):
            for name in try_sql(n, f"SELECT name FROM system.{kind} ORDER BY name FORMAT TSV").splitlines():
                if name and not name.startswith("error"):
                    acl.append(try_sql(n, f"SHOW CREATE {show} `{name}`" if kind != "row_policies"
                                       else f"SHOW CREATE ROW POLICY {name}"))
        acl.append(try_sql(n, "SELECT user_name, role_name, access_type, database, table, column, is_partial_revoke, "
                              "grant_option FROM system.grants ORDER BY ALL FORMAT TSV"))
        acl.append(try_sql(n, "SELECT user_name, role_name, granted_role_name, with_admin_option FROM "
                              "system.role_grants ORDER BY ALL FORMAT TSV"))
        acl.append(try_sql(n, "SELECT name, storage, auth_type, host_ip, default_roles_all, default_database "
                              "FROM system.users ORDER BY name FORMAT TSV"))
        s["acl"] = "\n".join(acl)
        s["definitions"] = try_sql(n, "SELECT name, create_table_query FROM system.tables WHERE database = 'ooni' "
                                      "ORDER BY name FORMAT TSV")
        s["content"] = content(n)
        s["queries"], s["api_queries"] = {}, {}
        for i, q in enumerate(queries()):
            s["queries"][i] = try_sql(n, q + " FORMAT TSVWithNames", timeout=120)
            r = try_sql(n, q + " FORMAT TSVWithNames", as_user("oonimeasurements"), timeout=120)
            s["api_queries"][i] = r if r.startswith("error") else ("same as admin" if r == s["queries"][i] else r)
        s["old_logins"] = {u: try_sql(n, "SELECT currentUser()", ["-u", u, "--password", "old-" + u])
                           for u in ("oonimeasurements", "fastpath", "ooniprobe")}
        s["warnings"] = try_sql(n, "SELECT message FROM system.warnings FORMAT TSV")
        s["replicas"] = try_sql(n, "SELECT table, is_readonly, queue_size, absolute_delay FROM system.replicas "
                                   "WHERE is_readonly OR queue_size > 0 OR absolute_delay > 0 FORMAT TSV")
        s["errors"] = sh(n, "grep -h -E '<(Error|Fatal|Warning)>' /var/log/clickhouse-server/clickhouse-server.err.log "
                            "2>/dev/null | sed -E 's/^[0-9.: -]+ \\[ *[0-9]+ \\] \\{[^}]*\\} //' | "
                            "sed -E 's/^[0-9.: -]+ \\[ *[0-9]+ \\] //' | cut -c1-220 | sort | uniq -c | sort -rn | head -40")[1]
        json.dump(s, open(os.path.join(nd, "snapshot.json"), "w"), indent=1, sort_keys=True)
    return snap


def queries():
    return [l.strip() for l in open(os.path.join(HERE, "queries.sql")) if l.strip() and not l.startswith("--")]


# --- traffic during the rollout ------------------------------------------------------------

class Traffic(threading.Thread):
    """Like production's: every half second an insert into fastpath on data1 as the fastpath
    user (the fastpath service writes to clickhouse1), and an API query as oonimeasurements on
    data1 and data2 in turn (the API proxy's two upstreams)"""
    def __init__(self):
        super().__init__(daemon=True)
        self.inserted, self.insert_errors, self.read_ok, self.read_errors = [], [], 0, []
        self.events = []  # (time, insert succeeded)
        self.stop, self.i = threading.Event(), 0

    def run(self):
        readers = ["data1", "data2"]
        while not self.stop.is_set():
            node = "data1"
            uid = f"upgradetest-{self.i:06d}"
            r = try_sql(node, f"INSERT INTO ooni.fastpath (measurement_uid, report_id, input, probe_cc, test_name, "
                              f"measurement_start_time) VALUES ('{uid}', 'r-{uid}', '', 'ZZ', 'web_connectivity', "
                              f"now())", as_user("fastpath"))
            (self.insert_errors.append((node, r)) if r.startswith("error") else self.inserted.append(uid))
            self.events.append((time.time(), not r.startswith("error")))
            reader = readers[self.i % 2]
            r = try_sql(reader, "SELECT probe_cc, count() FROM ooni.fastpath WHERE "
                        "measurement_start_time >= '2026-10-01' AND measurement_start_time < '2026-10-01 01:00:00' "
                        "GROUP BY probe_cc ORDER BY probe_cc FORMAT TSV", as_user("oonimeasurements"))
            if r.startswith("error"):
                self.read_errors.append((reader, r))
            else:
                self.read_ok += 1
            self.i += 1
            time.sleep(0.5)

    def outage(self, since):
        """(longest stretch without a successful insert since `since`, in seconds, from the last
        success before the first failure to the next success; failed inserts)"""
        ev = [e for e in self.events if e[0] >= since]
        longest, last_ok, failing, failed = 0.0, since, False, 0
        for t, ok in ev:
            if ok:
                if failing:
                    longest = max(longest, t - last_ok)
                failing, last_ok = False, t
            else:
                failing, failed = True, failed + 1
        if failing and ev:
            longest = max(longest, ev[-1][0] - last_ok)
        return longest, failed

    def take(self):
        s = (len(self.inserted), list(self.insert_errors), self.read_ok, list(self.read_errors))
        self.insert_errors.clear()
        self.read_errors.clear()
        return s


def keeper_role(node):
    rc, out, _ = sh(node, "exec 3<>/dev/tcp/127.0.0.1/9181 && printf mntr >&3 && timeout 3 cat <&3", timeout=10)
    m = re.search(r"zk_server_state\s+(\w+)", out)
    return m.group(1) if m else "unreachable"


def keeper_quorum():
    """'leader <node>, <n> synced followers' from mntr, or what's wrong"""
    leaders = []
    for n in NODES:
        rc, out, _ = sh(n, "exec 3<>/dev/tcp/127.0.0.1/9181 && printf mntr >&3 && timeout 3 cat <&3", timeout=10)
        if re.search(r"zk_server_state\s+leader", out):
            m = re.search(r"zk_synced_followers\s+(\d+)", out)
            leaders.append((n, int(m.group(1)) if m else -1))
    if len(leaders) != 1:
        return False, f"{len(leaders)} leaders"
    return leaders[0][1] == len(NODES) - 1, f"leader {leaders[0][0]}, {leaders[0][1]} synced followers"


def ddl_probe(name, node):
    """Through Keeper and the distributed DDL queue: a new replicated table ON CLUSTER, a row
    inserted on node, read back on every node, and the table dropped ON CLUSTER"""
    t = f"default.upgrade_probe_{name}"
    try:
        sql(node, f"CREATE TABLE {t} ON CLUSTER oonidata_cluster (x UInt32) ENGINE = ReplicatedMergeTree("
                  f"'/clickhouse/{{cluster}}/tables/default/upgrade_probe_{name}', '{{replica}}') ORDER BY x", timeout=200)
        sql(node, f"INSERT INTO {t} VALUES (42)")
        for n in NODES:
            sql(n, f"SYSTEM SYNC REPLICA {t}", timeout=120)
            if sql(n, f"SELECT sum(x) FROM {t}") != "42":
                return False, f"{n} doesn't have the row"
        sql(node, f"DROP TABLE {t} ON CLUSTER oonidata_cluster SYNC", timeout=200)
        return True, "ok"
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        return False, (str(e).splitlines() or ["timeout"])[0][:200]


def manual_install(node, version):
    """What the runbook says to do when the role can't: install version's packages with apt,
    allowing a downgrade, and restart"""
    pkgs = " ".join(f"{p}={version}" for p in ("clickhouse-server", "clickhouse-client", "clickhouse-common-static"))
    rc, out, err = sh(node, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y -q --allow-downgrades "
                            f"-o Dpkg::Options::=--force-confold {pkgs} && systemctl restart clickhouse-server", timeout=900)
    open(os.path.join(OUT, f"manual-{node}.log"), "w").write(out + "\n" + err)
    return rc


def restart_seconds(node, since):
    """How long the server was down in its last restart after `since` (epoch): from 'Received
    termination signal' to the next 'Ready for connections' in its log; None if it didn't restart"""
    rc, out, _ = sh(node, "grep -h -E 'Received termination signal|Ready for connections' "
                          "/var/log/clickhouse-server/clickhouse-server.log | tail -4")
    stamps = []
    for line in out.splitlines():
        m = re.match(r"(\d{4})\.(\d\d)\.(\d\d) (\d\d):(\d\d):(\d\d)\.(\d+)", line)
        if m:
            y, mo, d, h, mi, sec, frac = m.groups()
            t = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(sec))) + float("0." + frac)  # hosts run UTC
            stamps.append((t, "Ready" in line))
    stop = [t for t, ready in stamps if not ready and t >= since - 2]
    if not stop:
        return None
    ready = [t for t, r in stamps if r and t >= stop[-1]]
    return round(ready[0] - stop[-1], 1) if ready else None


def wait_keeper(node, seconds=90):
    for _ in range(seconds // 2):
        if try_sql(node, "SELECT count() FROM system.zookeeper WHERE path = '/'").isdigit():
            return True
        time.sleep(2)
    return False


def save_progress(report):
    """The rollout table and timings so far, so that a later failure doesn't lose them"""
    open(os.path.join(OUT, "rollout.md"), "w").write("\n".join(report) + "\n")
    json.dump(TIMINGS, open(os.path.join(OUT, "timings.json"), "w"))


def rollout(phase, inv, roles, version, traffic, report, manual_fallback=False):
    """Deploys the branch's role to each host in ORDER, with clickhouse_version = version. With
    manual_fallback, a host the role fails on gets the packages with apt instead, and then the role
    again"""
    set_version(inv, version)
    playbook = os.path.join(UPGRADE, "deploy.yml")
    prev = (0, 0)
    for step, n in enumerate(ORDER, 1):
        step_started = time.time()
        rc, took, recap, changed = deploy(f"{phase}-{n}", inv, playbook, roles, limit=NODES[n])
        how = "role"
        if rc and manual_fallback:
            log_tail = open(os.path.join(OUT, f"ansible-{phase}-{n}.log")).read()
            fatal = [l for l in log_tail.splitlines() if l.startswith("fatal:")]
            notes.append(f"{phase} step {step}: the role failed on {n}: {(fatal or ['?'])[0][:400]}")
            log(f"     the role failed on {n}; installing {version} with apt instead")
            check(manual_install(n, version) == 0, f"{phase} step {step}: apt installs {version} on {n} and restarts it")
            rc, took2, recap, changed = deploy(f"{phase}-{n}-again", inv, playbook, roles, limit=NODES[n])
            took += took2
            how = "apt, then role"
        check(rc == 0, f"{phase} step {step}: the role deploys {n} ({how}, {took:.0f}s)")
        check(try_sql(n, "SELECT version()") == version, f"{phase} step {step}: {n} runs {version}")
        for other in NODES:
            check(wait_keeper(other), f"{phase} step {step}: {other} answers and reaches Keeper")
        for _ in range(30):
            quorum_ok, quorum = keeper_quorum()
            if quorum_ok:
                break
            time.sleep(2)
        check(quorum_ok, f"{phase} step {step}: Keeper has a leader and all followers synced ({quorum})")
        probe_ok, probe = ddl_probe(f"{phase}{step}".lower(), n)
        check(probe_ok, f"{phase} step {step}: ON CLUSTER DDL and a new replicated table work ({probe})")
        time.sleep(3)
        down = restart_seconds(n, step_started)
        gap, gap_failed = traffic.outage(step_started)
        TIMINGS.append((phase, step, n, took, down, gap, gap_failed))
        ins, ins_err, reads, read_err = traffic.take()
        state = {o: (try_sql(o, "SELECT version()"), keeper_role(o)) for o in NODES}
        report.append(f"| {phase} | {step} | {n} ({how}) | {took:.0f} | "
                      f"{'no restart' if down is None else down} | {gap:.1f} | {ins - prev[0]} / {len(ins_err)} | "
                      f"{reads - prev[1]} / {len(read_err)} | {quorum} | {probe} | "
                      + ", ".join(f"{o} {v} ({k})" for o, (v, k) in state.items()) + " |")
        for node, e in (ins_err + read_err)[:6]:
            notes.append(f"{phase} step {step} ({n} deployed): {node}: {e[:200]}")
        report.append(f"<!-- changed tasks on {n}: {', '.join(changed) or 'none'} -->")
        prev = (ins, reads)
        save_progress(report)


# --- comparing snapshots -------------------------------------------------------------------

def diff(a, b, name):
    return "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), f"{name} before", f"{name} after",
                                          n=0, lineterm=""))


def compare(before, after, label, lines, content_only=False):
    lines.append(f"\n## {label}\n")
    n0 = "data1"
    for n in NODES:
        b, a = before[n], after[n]
        for t in sorted(set(b["content"]) | set(a["content"])):
            check(b["content"].get(t) == a["content"].get(t),
                  f"{label}: {n}: ooni.{t} has the same rows ({a['content'].get(t)})")
        for i in b["queries"]:
            same = b["queries"][i] == a["queries"][i]
            check(same and not a["queries"][i].startswith("error"), f"{label}: {n}: query {int(i) + 1} gives the same result")
            if not same:
                lines.append(f"query {int(i) + 1} on {n}:\n```diff\n{diff(b['queries'][i], a['queries'][i], 'result')[:3000]}\n```")
        if content_only:
            continue
        for i in b["api_queries"]:
            x, y = b["api_queries"][i], a["api_queries"][i]
            if x != y:
                check(x.startswith("error") or not y.startswith("error"),
                      f"{label}: {n}: query {int(i) + 1} as oonimeasurements still works ({y[:160]})")
                lines.append(f"- {n}: query {int(i) + 1} as oonimeasurements: `{x[:200]}` -> `{y[:200]}`")
        for u in b["old_logins"]:
            x, y = b["old_logins"][u], a["old_logins"][u]
            if x.startswith("error") != y.startswith("error"):
                lines.append(f"- {n}: {u} with its old password: `{x[:120]}` -> `{y[:120]}`")
        for u in USERS:
            ok_before = not b["logins"][u].startswith("error")
            check(not ok_before or not a["logins"][u].startswith("error"),
                  f"{label}: {n}: {u} can still log in ({a['logins'][u][:80]})")
        sections = [("settings each user gets", "\n".join(f"[{u}]\n{b['settings'][u]}" for u in USERS),
                     "\n".join(f"[{u}]\n{a['settings'][u]}" for u in USERS)),
                    ("users, roles, quotas, profiles, grants", b["acl"], a["acl"]),
                    ("server settings", b["server_settings"], a["server_settings"]),
                    ("table definitions", b["definitions"], a["definitions"]),
                    ("packages", b["packages"], a["packages"]),
                    ("systemd unit", b["unit"], a["unit"])]
        for f in sorted(set(b["files"]) | set(a["files"])):
            sections.append((f, b["files"].get(f, "(missing)"), a["files"].get(f, "(missing)")))
        for title, x, y in sections:
            if x != y:
                lines.append(f"### {n}: {title}\n```diff\n{diff(x, y, title)[:6000]}\n```")
        if a["warnings"]:
            lines.append(f"### {n}: system.warnings\n```\n{a['warnings']}\n```")
        if a["errors"]:
            lines.append(f"### {n}: errors and warnings logged so far (count, message)\n```\n{a['errors']}\n```")
    if content_only:
        return
    for n in NODES:  # every node has the same data as data1
        for t in ("fastpath", "obs_web", "obs_web_ctrl", "analysis_web_measurement", "citizenlab", "jsonl"):
            if t in after[n0]["content"]:
                check(after[n]["content"].get(t) == after[n0]["content"][t], f"{label}: {n} has data1's ooni.{t}")


# --- the test ------------------------------------------------------------------------------

def final_checks(label, version, inserted):
    for n in NODES:
        sync(n)
        check(try_sql(n, "SELECT version()") == version, f"{label}: {n} runs {version}")
        check(sql(n, "SELECT count() FROM system.replicas WHERE is_readonly OR is_session_expired") == "0",
              f"{label}: {n} has no read-only replicated tables")
        check(sql(n, "SELECT count() FROM system.replication_queue WHERE num_tries > 10") == "0",
              f"{label}: {n} has no replication task failing over and over")
        have = set(sql(n, "SELECT measurement_uid FROM ooni.fastpath WHERE measurement_uid LIKE 'upgradetest-%' "
                          "FORMAT TSV").split())
        missing = [u for u in inserted if u not in have]
        check(not missing, f"{label}: {n} has all {len(inserted)} rows whose insert succeeded (missing {missing[:3]})")


REPORT_HEAD = ["| phase | step | deployed (how) | role run (s) | ClickHouse down (s) | longest fastpath write gap "
               "on data1 (s) | inserts ok / failed | reads ok / failed | Keeper | ON CLUSTER probe | cluster after |",
               "|---|---|---|---|---|---|---|---|---|---|---|"]
TIMINGS = []  # (phase, step, node, role seconds, restart seconds, write gap seconds, failed inserts)


def downgrade(traffic, report, s1, s2, lines):
    """C: back to FROM's version with the branch's role, one host at a time"""
    inv_from, inv_to = os.path.join(OUT, "inventory-from"), os.path.join(OUT, "inventory-to")
    from_version, to_version = version_in(inv_from), s2["data1"]["version"]
    rollout("C", inv_to, os.path.join(ANSIBLE, "roles"), from_version, traffic, report, manual_fallback=True)
    time.sleep(5)
    final_checks("C", from_version, list(traffic.inserted))
    s3 = snapshot("C-downgrade")
    compare(s2, s3, f"C: {to_version} -> {from_version} (downgrade)", lines)
    compare(s1, s3, f"C compared with A (both {from_version}, the branch's role)", lines, content_only=True)
    return s3


def finish(lines, name="report.md"):
    lines.append("\n## Notes\n")
    lines += [f"- {x}" for x in notes]
    lines.append("\n## Result\n")
    lines.append(f"{len(failures)} checks failed:\n" + "\n".join(f"- {f}" for f in failures) if failures
                 else "All checks passed.")
    open(os.path.join(OUT, name), "w").write("\n".join(lines) + "\n")
    json.dump(TIMINGS, open(os.path.join(OUT, name.replace(".md", "-timings.json")), "w"))
    log(f"\nreport: {os.path.join(OUT, name)}")
    log(f"\n{len(failures)} failed" if failures else "\nall passed")
    sys.exit(1 if failures else 0)


def main_downgrade():
    """Phase C alone, on the hosts a run with KEEP=1 left at the new version"""
    load = lambda label: {n: json.load(open(os.path.join(OUT, "snap", label, n, "snapshot.json"))) for n in NODES}
    s1, s2 = load("A-branch-role"), load("B-version-hop")
    lines = [f"# Live-data downgrade test: {s2['data1']['version']} -> {version_in(os.path.join(OUT, 'inventory-from'))}\n",
             f"On the hosts left by the upgrade run (see report.md), order {' '.join(ORDER)}.\n", "## Rollout\n"]
    report = list(REPORT_HEAD)
    traffic = Traffic()
    traffic.i = 500000  # its rows apart from the upgrade run's
    traffic.start()
    try:
        tail = []
        downgrade(traffic, report, s1, s2, tail)
    finally:
        traffic.stop.set()
        traffic.join()
    lines += report + tail
    finish(lines, "report-downgrade.md")


def main():
    os.makedirs(os.path.join(CACHE, "debs"), exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    from_ansible, from_roles, galaxy_version = prepare_from()
    inv_from, inv_to = os.path.join(OUT, "inventory-from"), os.path.join(OUT, "inventory-to")
    write_inventory(inv_from, from_ansible)
    write_inventory(inv_to, ANSIBLE)
    from_version, to_version = version_in(inv_from), version_in(inv_to)
    log(f"FROM {FROM_REF} (galaxy idealista.clickhouse_role {galaxy_version}, ClickHouse {from_version}); "
        f"A: this branch's role at {from_version}; B: {to_version}; order {' '.join(ORDER)}")
    report = list(REPORT_HEAD)

    r = compose("up", "-d", "--build", "--quiet-pull")
    if not check(r.returncode == 0, "the three hosts start"):
        sys.exit(r.stderr[-2000:])
    for n in NODES:
        for _ in range(30):  # right after start, exec can run before systemd answers
            rc, state, _ = sh(n, "systemctl is-system-running --wait", timeout=180)
            if state in ("running", "degraded"):
                break
            time.sleep(2)
        check(state in ("running", "degraded"), f"{n} boots with systemd ({state})")

    # 0: what production runs today
    rc, took, recap, _ = deploy("from", inv_from, os.path.join(OUT, "from-deploy.yml"), from_roles)
    if not check(rc == 0, f"main's role installs {from_version} on the three hosts ({took:.0f}s)"):
        sys.exit(1)
    for n in NODES:
        check(wait_keeper(n), f"{n} answers and reaches Keeper")
    schema = subprocess.run(["git", "-C", REPO, "show", f"{SCHEMA_REF}:scripts/cluster-migration/schema.sql"],
                            capture_output=True, text=True, check=True).stdout
    sql("data1", "CREATE DATABASE IF NOT EXISTS ooni ON CLUSTER oonidata_cluster")
    run(["docker", "exec", "-i", "chlive-data1", "clickhouse-client", *ADMIN, "--database", "ooni", "--multiquery"],
        input=schema, timeout=600, check=True)
    check(all(len(tables(n)) >= 20 for n in NODES), "production's schema is on the three hosts")
    counts = load_sample()
    log("sample: " + ", ".join(f"{t} {c}" for t, c in counts.items() if c != "0"))
    if os.environ.get("SEEDS", "1") != "0":
        apply_seeds()
    s0 = snapshot("0-main")

    traffic = Traffic()
    traffic.start()
    roles = os.path.join(ANSIBLE, "roles")
    rollout("A", inv_to, roles, from_version, traffic, report)
    for n in NODES:
        sync(n)
    s1 = snapshot("A-branch-role")
    rollout("B", inv_to, roles, to_version, traffic, report)
    time.sleep(5)
    final_checks("B", to_version, list(traffic.inserted))
    s2 = snapshot("B-version-hop")
    tail = []
    if os.environ.get("DOWNGRADE", "1") != "0":
        downgrade(traffic, report, s1, s2, tail)
    traffic.stop.set()
    traffic.join()

    lines = [f"# Live-data upgrade test: {from_version} -> {to_version}\n",
             f"From {FROM_REF} (galaxy role {galaxy_version}), schema.sql at {SCHEMA_REF}, sample "
             f"{WINDOW[0]} to {WINDOW[1]} from `{' '.join(SAMPLE_CLIENT)}`, order {' '.join(ORDER)}.\n",
             "## Sample\n", "| table | rows |", "|---|---|"]
    lines += [f"| {t} | {c} |" for t, c in counts.items()]
    lines += ["\n## Rollout\n"] + report
    compare(s0, s1, "A: main -> this branch's role, same version", lines)
    compare(s1, s2, f"B: {from_version} -> {to_version}", lines)
    finish(lines + tail)


if __name__ == "__main__":
    main_downgrade() if sys.argv[1:] == ["downgrade"] else main()
