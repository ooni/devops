#!/usr/bin/env python3
"""
Runs the role's SQL-driven tasks (users, quotas, grants) with the real
ansible/group_vars/clickhouse/vars.yml against ClickHouse containers (compose.yml):
`fresh` starts empty, data1-3 are seeded like the production nodes (seed/), and checks
that:

- every node ends up with the users, privileges and quota limits of an empty node that
  only ever had the role, keeping user ids, quota assignments, roles granted by hand and
  objects not in vars;
- every user logs in with its password from vars (and not with an old one), can do what
  its grants allow and nothing else, and has the settings from vars, CONST ones fixed;
- a second run changes nothing;
- queries running during the role runs never lose their privileges;
- task output never shows a password or its hash, and errors are visible;
- with clickhouse_sql_objects_drop_unlisted, objects not in vars are dropped.

Called by run.sh; needs ansible-playbook and PyYAML.
"""
import base64, hashlib, json, os, re, subprocess, sys, threading, time, urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
ROLES = os.path.normpath(os.path.join(TESTS, "../.."))
VARS = os.path.normpath(os.path.join(ROLES, "../group_vars/clickhouse/vars.yml"))
OUT = os.path.join(TESTS, "out")
COMPOSE = os.environ.get("COMPOSE", "docker compose").split() + ["-f", os.path.join(TESTS, "compose.yml")]
NODES = {"fresh": 18120, "data1": 18121, "data2": 18122, "data3": 18123}
SEEDED = ["data1", "data2", "data3"]
failures = []


def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)


# --- test vars: production's vars.yml, with the AWS lookups replaced by test secrets -------

def write_test_vars():
    text = open(VARS).read()
    text = re.sub(r"lookup\('amazon\.aws\.aws_(?:ssm|secret)', '([^']+)'[^)]*\)",
                  lambda m: "'test-" + m.group(1).rsplit("/", 1)[-1] + "'", text)
    os.makedirs(OUT, exist_ok=True)
    open(os.path.join(OUT, "vars.yml"), "w").write(text)
    import yaml
    v = yaml.safe_load(text)
    # each user's password is "{{ 'test-...' | hash('sha256') }}"
    passwords = {u["name"]: re.search(r"'([^']+)' \| hash\('sha256'\)", u["password"]).group(1)
                 for u in v["clickhouse_custom_users"]}
    admin = re.fullmatch(r"\{\{ '([^']+)' \}\}", v["clickhouse_admin_password"]).group(1)
    return v, passwords, admin


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


# --- ClickHouse access ---------------------------------------------------------------

def admin_sql(node, sql):
    """As admin, inside the node's container (admin may only connect from localhost)."""
    r = subprocess.run(COMPOSE + ["exec", "-T", node, "clickhouse-client", "-u", ADMIN_USER,
                                  "--password", ADMIN_PASSWORD, "--multiquery"],
                       input=sql, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"{node}: {r.stderr.strip()}")
    return r.stdout


def user_sql(node, user, password, sql):
    """As a service user, over HTTP. Returns (ok, text): text is the error on failure."""
    req = urllib.request.Request(f"http://127.0.0.1:{NODES[node]}/", data=sql.encode(), headers={
        "X-ClickHouse-User": user, "X-ClickHouse-Key": password})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return True, r.read().decode().strip()
    except urllib.error.HTTPError as e:
        return False, e.read().decode().strip()
    except OSError as e:
        return False, str(e)


def error_code(text):
    m = re.search(r"Code: (\d+)", text)
    return int(m.group(1)) if m else None


def state(node):
    """What the role manages on a node: users, grants, quotas and SQL objects not in vars."""
    s = {"ids": {}, "users": {}, "quotas": {}}
    for line in admin_sql(node, "SELECT name, id FROM system.users WHERE storage = 'local_directory' FORMAT TSV").splitlines():
        name, uid = line.split("\t")
        s["ids"][name] = uid
    for u in V["clickhouse_custom_users"]:
        if u["name"] in s["ids"]:
            grants = admin_sql(node, f"SHOW GRANTS FOR {u['name']}").splitlines()
            # privileges ("GRANT ... ON ..."), which the role manages, apart from granted roles
            s["users"][u["name"]] = (admin_sql(node, f"SHOW CREATE USER {u['name']}").strip(),
                                     [g for g in grants if " ON " in g])
            s.setdefault("roles", {})[u["name"]] = [g for g in grants if " ON " not in g]
    names = admin_sql(node, "SELECT name FROM system.quotas WHERE storage = 'local_directory' FORMAT TSV").split()
    for q in names:
        s["quotas"][q] = admin_sql(node, f"SHOW CREATE QUOTA {q}").strip()
    return s


def quota_limits(show_create):
    return re.sub(r" TO .*$", "", show_create)


def quota_to(show_create):
    m = re.search(r" TO (.*)$", show_create)
    return m.group(1) if m else None


# --- running the role ----------------------------------------------------------------

def run_role(label, limit=None, extra=None):
    inventory = os.path.join(OUT, "inventory.ini")
    open(inventory, "w").write("\n".join(NODES) + "\n")
    cmd = ["ansible-playbook", "-i", inventory, os.path.join(TESTS, "play.yml"),
           "-e", "@" + os.path.join(OUT, "vars.yml")]
    if limit:
        cmd += ["--limit", limit]
    if extra:
        cmd += ["-e", json.dumps(extra)]
    env = dict(os.environ, ANSIBLE_ROLES_PATH=ROLES, TESTS=TESTS, ANSIBLE_NOCOLOR="1",
               ANSIBLE_PYTHON_INTERPRETER=sys.executable, COMPOSE=" ".join(COMPOSE[:-2]))
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    log = r.stdout + r.stderr
    open(os.path.join(OUT, f"ansible-{label}.log"), "w").write(log)
    if r.returncode and label != "error":  # the "error" run is meant to fail
        print(log[-3000:])
    return r.returncode, log


def leaks(log):
    """Passwords or password hashes from the test vars that appear in ansible's output."""
    secrets = [ADMIN_PASSWORD, sha256(ADMIN_PASSWORD)]
    for p in PASSWORDS.values():
        secrets += [p, sha256(p)]
    return [s[:12] + "..." for s in secrets if s in log]


class Probe(threading.Thread):
    """Inserts as fastpath and selects as oonimeasurements on a node until stopped."""
    def __init__(self, node):
        super().__init__(daemon=True)
        self.node, self.ok, self.errors, self.stop = node, 0, [], threading.Event()

    def run(self):
        while not self.stop.is_set():
            for user, sql in (("fastpath", "INSERT INTO ooni.fastpath VALUES (1)"),
                              ("oonimeasurements", "SELECT count() FROM ooni.probe")):
                ok, text = user_sql(self.node, user, PASSWORDS[user], sql)
                if ok:
                    self.ok += 1
                else:
                    self.errors.append(f"{user}: {text[:120]}")


# --- per-user checks derived from vars ---------------------------------------------------

def granted(user, privilege, database, table):
    return any(user in g["to"] and privilege in g["privileges"] and database in g["databases"]
               and (table in g["tables"] or "*" in g["tables"]) for g in V["clickhouse_custom_grants"])


def grant_universe():
    """Every database.table the grants name, with "*" as the table `probe`, and extra.t,
    which no one is granted, so that a too broad grant shows."""
    tables = {("extra", "t")}
    for g in V["clickhouse_custom_grants"]:
        for d in g["databases"]:
            for t in g["tables"]:
                tables.add((d, "probe" if t == "*" else t))
    return sorted(tables)


def check_user(node, user):
    name, password = user["name"], PASSWORDS[user["name"]]
    ok, text = user_sql(node, name, password, "SELECT currentUser()")
    check(ok and text == name, f"{node}: {name} logs in with its password from vars")
    for database, table in grant_universe():
        for privilege, sql in (("SELECT", f"SELECT count() FROM {database}.{table}"),
                               ("INSERT", f"INSERT INTO {database}.{table} VALUES (1)")):
            ok, text = user_sql(node, name, password, sql)
            want = granted(name, privilege, database, table)
            check(ok == want and (ok or error_code(text) == 497),
                  f"{node}: {name} {'can' if want else 'cannot'} {privilege} {database}.{table}")
    for setting in user.get("settings", []):
        key, value, const = re.fullmatch(r"(\w+) = (\S+)( CONST)?", setting).groups()
        ok, text = user_sql(node, name, password, f"SELECT getSetting('{key}')")
        check(ok and float(text) == float(value), f"{node}: {name} has {key} = {value}")
        if const:
            ok, text = user_sql(node, name, password, f"SELECT 1 SETTINGS {key} = {int(float(value)) * 2}")
            check(not ok and error_code(text) == 452, f"{node}: {name} cannot raise {key}")
    ok, text = user_sql(node, name, password, "SELECT 1 SETTINGS log_comment = 'test'")
    check(ok, f"{node}: {name} can set log_comment")


# --- the test ------------------------------------------------------------------------

def setup():
    tables = grant_universe()
    ddl = "".join(f"CREATE DATABASE IF NOT EXISTS {d};\n" for d in sorted({d for d, _ in tables} | {"extra"}))
    ddl += "".join(f"CREATE TABLE IF NOT EXISTS {d}.{t} (x UInt8) ENGINE = Memory;\n" for d, t in tables)
    for node in NODES:
        for _ in range(60):
            try:
                admin_sql(node, "SELECT 1")
                break
            except RuntimeError:
                time.sleep(1)
        admin_sql(node, ddl)
    for node in SEEDED:
        sql = open(os.path.join(TESTS, "seed", f"{node}.sql")).read()
        sql = re.sub(r"\{password:(\w+)\}", lambda m: sha256(PASSWORDS[m.group(1)]), sql)
        sql = re.sub(r"\{old_password:(\w+)\}", lambda m: sha256("old-" + m.group(1)), sql)
        admin_sql(node, sql)


def main():
    global V, PASSWORDS, ADMIN_USER, ADMIN_PASSWORD
    V, PASSWORDS, ADMIN_PASSWORD = write_test_vars()
    ADMIN_USER = V["clickhouse_admin_user"]
    if sys.argv[1:] == ["render"]:  # run.sh renders users.xml before starting the containers
        return
    setup()
    before = {n: state(n) for n in NODES}
    check(user_sql("data3", "oonimeasurements", PASSWORDS["oonimeasurements"], "SELECT 1")[0] is False,
          "data3: before the role, oonimeasurements has an old password")

    probe = Probe("data1")
    probe.start()
    rc1, log1 = run_role("run1")
    rc2, log2 = run_role("run2")
    probe.stop.set()
    probe.join()
    check(rc1 == 0, "first role run succeeds")
    check(rc2 == 0, "second role run succeeds")
    check(not probe.errors and probe.ok > 20,
          f"data1: {probe.ok} queries during the runs, failures: {probe.errors[:3]}")
    check(not leaks(log1 + log2), f"no password or hash in the output: {leaks(log1 + log2)}")
    # What the probe can't catch reliably, a gap between two statements, can't happen if
    # the role never revokes a privilege a user keeps: all users in vars have grants, so it
    # sends no REVOKE at all.
    for n in NODES:
        admin_sql(n, "SYSTEM FLUSH LOGS")
        revokes = admin_sql(n, "SELECT count() FROM system.query_log WHERE type = 'QueryStart' "
                               f"AND user = '{ADMIN_USER}' AND query ILIKE '%REVOKE%'").strip()
        check(revokes == "0", f"{n}: the role sent no REVOKE ({revokes})")

    after = {n: state(n) for n in NODES}
    for node in NODES:
        users = after[node]["users"]
        check(set(users) == {u["name"] for u in V["clickhouse_custom_users"]}, f"{node}: every user in vars exists")
        if node != "fresh":
            check(users == after["fresh"]["users"], f"{node}: users and grants are those of a fresh node")
            kept = {n: i for n, i in before[node]["ids"].items() if n in after[node]["ids"]}
            check(all(after[node]["ids"][n] == i for n, i in kept.items()), f"{node}: user ids are kept")
            check(set(before[node]["ids"]) <= set(after[node]["ids"]), f"{node}: users not in vars are kept")
            check(set(before[node]["quotas"]) <= set(after[node]["quotas"]), f"{node}: quotas not in vars are kept")
            check(after[node].get("roles") == {u: before[node].get("roles", {}).get(u, []) for u in after[node]["roles"]},
                  f"{node}: roles granted by hand are kept")
        for q in V["clickhouse_custom_quotas"]:
            show = after[node]["quotas"].get(q["name"], "")
            check(quota_limits(show) == quota_limits(after["fresh"]["quotas"][q["name"]]),
                  f"{node}: quota {q['name']} has the limits from vars")
            want_to = ", ".join(q["to"]) if "to" in q else quota_to(before[node]["quotas"].get(q["name"], ""))
            check(quota_to(show) == want_to, f"{node}: quota {q['name']} is assigned to {want_to or 'nobody'}")
        for user in V["clickhouse_custom_users"]:
            check_user(node, user)
    check(user_sql("data3", "oonimeasurements", "old-oonimeasurements", "SELECT 1")[0] is False,
          "data3: the old password no longer works")

    rc3, _ = run_role("run3")
    check(rc3 == 0 and {n: state(n) for n in NODES} == after, "a third run changes nothing")

    # An invalid setting fails the run, with ClickHouse's error and without the password hash
    bad = [dict(u, settings=u.get("settings", []) + ["not_a_setting = 1"]) if u["name"] == "oonimeasurements" else u
           for u in V["clickhouse_custom_users"]]
    rc, log = run_role("error", limit="data1", extra={"clickhouse_custom_users": bad})
    check(rc != 0 and "UNKNOWN_SETTING" in log, "an invalid setting fails with ClickHouse's error in the output")
    check(not leaks(log), f"no password or hash in the error output: {leaks(log)}")

    rc, _ = run_role("drop", limit="data1", extra={"clickhouse_sql_objects_drop_unlisted": True})
    s = state("data1")
    check(rc == 0 and "manual_user" not in s["ids"] and "manual_quota" not in s["quotas"],
          "data1: with clickhouse_sql_objects_drop_unlisted, users and quotas not in vars are dropped")
    check(s["users"] == after["fresh"]["users"], "data1: users in vars are unaffected by the drop")

    print(f"\n{len(failures)} failed" if failures else "\nall passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
