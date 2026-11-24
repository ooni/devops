#!/usr/bin/env python3
"""
Before deploying the clickhouse role: will every service still log in?

The role sets each ClickHouse user's password from an SSM parameter (group_vars/clickhouse:
`lookup('amazon.aws.aws_ssm', '/oonidevops/secrets/clickhouse_<user>_password')`, in the prod
account). The Ansible-deployed services (fastpath, testlists, ...) build their DSN from that
same parameter, but the API services deployed by Terraform read a whole DSN from another
parameter (`/oonidevops/secrets/clickhouse_<service>_url`, in the prod or the dev account),
whose password was typed in by hand. If the two differ, the role locks that service out.

For each DSN parameter in tf/environments/{prod,dev}/main.tf, this reads the DSN's user and
password, finds the parameter the role sets that user's password from, and prints whether they
match. It prints user names, hosts and databases, never a password.

    scripts/clickhouse_credentials_check.py [--prod-profile oonidevops_user_prod]
                                             [--dev-profile oonidevops_user_dev]

Needs boto3 and read access to both accounts' SSM parameters. Exits 1 on any mismatch.
"""
import argparse
import hashlib
import os
import re
import sys
from urllib.parse import unquote, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LOOKUP = re.compile(r"lookup\('amazon\.aws\.aws_ssm', '([^']+)', profile='([^']+)'\)")


def role_password_params(vars_text: str) -> dict:
    """{user: (ssm path, profile)} for the users group_vars/clickhouse defines, from the
    `name:` line before each password lookup"""
    out, name = {}, None
    for line in vars_text.splitlines():
        m = re.match(r"\s*-?\s*name:\s*\"?([\w{}\s]+?)\"?\s*$", line)
        if m:
            name = m.group(1).strip()
        m = LOOKUP.search(line)
        if m and name and re.search(r"password", line):
            out.setdefault(name, (m.group(1), m.group(2)))
    # the admin user's name and password come from their own variables
    m = re.search(r"^clickhouse_admin_password: .*" + LOOKUP.pattern, vars_text, re.M)
    if m:
        out["admin"] = (m.group(1), m.group(2))
    out.pop("{{ clickhouse_admin_user }}", None)
    return out


def dsn_params(tf_text: str) -> list:
    """the SSM paths of the CLICKHOUSE_URL parameters a Terraform environment uses"""
    names = set(re.findall(r"CLICKHOUSE_URL\s*=\s*data\.aws_ssm_parameter\.(\w+)\.", tf_text))
    paths = []
    for n in sorted(names):
        m = re.search(r'data "aws_ssm_parameter" "%s" \{\s*name\s*=\s*"([^"]+)"' % n, tf_text)
        if m:
            paths.append(m.group(1))
    return paths


def parse_dsn(dsn: str) -> tuple:
    u = urlparse(dsn)
    return unquote(u.username or "default"), unquote(u.password or ""), u.hostname, u.path.strip("/")


def digest(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    ap.add_argument("--prod-profile", default="oonidevops_user_prod")
    ap.add_argument("--dev-profile", default="oonidevops_user_dev")
    args = ap.parse_args()
    import boto3

    clients = {}

    def get(path, profile):
        if profile not in clients:
            clients[profile] = boto3.Session(profile_name=profile).client("ssm")
        return clients[profile].get_parameter(Name=path, WithDecryption=True)["Parameter"]["Value"]

    role = role_password_params(open(os.path.join(REPO, "ansible/group_vars/clickhouse/vars.yml")).read())
    profiles = {"prod": args.prod_profile, "dev": args.dev_profile}
    bad = 0
    for env, profile in profiles.items():
        tf = open(os.path.join(REPO, f"tf/environments/{env}/main.tf")).read()
        for path in dsn_params(tf):
            try:
                user, password, host, db = parse_dsn(get(path, profile))
            except Exception as e:
                print(f"ERROR     {env:4} {path}: can't read it ({type(e).__name__})")
                bad += 1
                continue
            where = f"{env:4} {path} -> {user}@{host}/{db}"
            if user not in role:
                print(f"UNKNOWN   {where}: the role doesn't manage a user {user!r}")
                bad += 1
                continue
            role_path, role_profile = role[user]
            same = digest(password) == digest(get(role_path, profile=args.prod_profile if role_profile == "oonidevops_user_prod" else args.dev_profile))
            print(f"{'MATCH' if same else 'MISMATCH':9} {where}: the role sets {user}'s password from {role_path}")
            bad += not same
    print(f"\n{bad} to fix before deploying the role" if bad else "\nevery service's DSN has the password the role sets")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
