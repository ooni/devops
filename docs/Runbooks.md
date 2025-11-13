# Runbooks

Below you will find runbooks for common tasks and operations to manage our infra.

## Monitoring deployment runbook

The monitoring stack is deployed and configured by
[Ansible](#tool:ansible) on the [monitoring.ooni.org](#monitoring.ooni.org)&thinsp;🖥
host using the following playbook:
<https://github.com/ooni/sysadmin/blob/master/ansible/deploy-monitoring-config.yml>

It includes:

- [Grafana](#grafana)&thinsp;🔧 at <https://grafana.ooni.org>

- [Jupyter Notebook](#jupyter-notebook)&thinsp;🔧 at <https://jupyter.ooni.org>

- [Vector](#tool:vector) (see [Log management](#log-management)&thinsp;💡)

- local [Netdata](#tool:netdata), [Blackbox exporter](#blackbox-exporter)&thinsp;🔧, etc

- [Prometheus](#prometheus)&thinsp;🔧 at <https://prometheus.ooni.org>

It also configures the FQDNs:

- loghost.ooni.org

- monitoring.ooni.org

- netdata.ooni.org

This also includes the credentials to access the Web UIs. They are
deployed as `/etc/nginx/monitoring.htpasswd` from
`ansible/roles/monitoring/files/htpasswd`

**Warning** the following steps are dangerously broken. Applying the changes
will either not work or worse break production.

If you must do something of this sort, you will unfortunately have to resort of
specifying the particular substeps you want to run using the `-t` tag filter
(eg. `-t prometheus-conf` to update the prometheus configuration.

Steps:

1.  Review [Ansible playbooks summary](#ansible-playbooks-summary)&thinsp;📒,
    [Deploying a new host](#run:newhost) [Grafana dashboards](#grafana-dashboards)&thinsp;💡.

2.  Run `./play deploy-monitoring.yml -l monitoring.ooni.org --diff -C`
    and review the output

3.  Run `./play deploy-monitoring.yml -l monitoring.ooni.org --diff` and
    review the output

## Updating Blackbox Exporter runbook

This runbook describes updating [Blackbox exporter](#blackbox-exporter)&thinsp;🔧.

The `blackbox_exporter` role in ansible is pulled in by the `deploy-monitoring.yml`
runbook.

The configuration file is at `roles/blackbox_exporter/templates/blackbox.yml.j2`
together with `host_vars/monitoring.ooni.org/vars.yml`.

To add a simple HTTP[S] check, for example, you can copy the "ooni website" block.

Edit it and run the deployment of the monitoring stack as described in the previous subchapter.

## Deploying a new host

To deploy a new host:

1.  Choose a FQDN like \$name.ooni.org based on the
    [DNS naming policy](#dns-naming-policy)&thinsp;💡

2.  Deploy the physical host or VM using Debian Stable

3.  Create `A` and `AAAA` records for the FQDN in the Namecheap web UI

4.  Follow [Updating DNS diagrams](#updating-dns-diagrams)&thinsp;📒

5.  Review the `inventory` file and git-commit it

6.  Deploy the required stack. Run ansible it test mode first. For
    example this would deploy a backend host:

        ./play deploy-backend.yml --diff -l <name>.ooni.org -C
        ./play deploy-backend.yml --diff -l <name>.ooni.org

7.  Update [Prometheus](#prometheus)&thinsp;🔧 by following
    [Monitoring deployment runbook](#monitoring-deployment-runbook)&thinsp;📒

8.  git-push the commits

Also see [Monitoring deployment runbook](#monitoring-deployment-runbook)&thinsp;📒 for an
example of deployment.

## Deleting a host

1. Remove it from `inventory`

2. Update the monitoring deployment using:

```
./play deploy-monitoring.yml -t prometheus-conf -l monitoring.ooni.org --diff
```

## Weekly measurements review runbook

On a daily or weekly basis the following dashboards and Jupyter notebooks can be reviewed to detect unexpected patterns in measurements focusing on measurement drops, slowdowns or any potential issue affecting the backend infrastructure.

When browsing the dashboards expand the time range to one year in order to spot long term trends.
Also zoom in to the last month to spot small glitches that could otherwise go unnoticed.

Review the [API and fastpath](#api-and-fastpath)&thinsp;📊 dashboard for the production backend host[s] for measurement flow, CPU and memory load,
timings of various API calls, disk usage.

Review the [Incoming measurements notebook](#incoming-measurements-notebook)&thinsp;📔 for unexpected trends.

Quickly review the following dashboards for unexpected changes:

 * [Long term measurements prediction notebook](#long-term-measurements-prediction-notebook)&thinsp;📔
 * [Test helpers dashboard](#test-helpers-dashboard)&thinsp;📊
 * [Test helper failure rate notebook](#test-helper-failure-rate-notebook)&thinsp;📔
 * [Database backup dashboard](#database-backup-dashboard)&thinsp;📊
 * [GeoIP MMDB database dashboard](#geoip-mmdb-database-dashboard)&thinsp;📊
 * [GeoIP dashboard](#geoip-mmdb-database-dashboard)&thinsp;📊
 * [Fingerprint updater dashboard](#fingerprint-updater-dashboard)&thinsp;📊
 * [ASN metadata updater dashboard](#asn-metadata-updater-dashboard)&thinsp;📊

Also check <https://jupyter.ooni.org/view/notebooks/jupycron/summary.html> for glitches like notebooks not being run etc.


## Grafana backup runbook
This runbook describes how to back up dashboards and alarms in Grafana.
It does not include backing up datapoints stored in
[Prometheus](#prometheus)&thinsp;🔧.

The Grafana SQLite database can be dumped by running:

```bash
sqlite3 -line /var/lib/grafana/grafana.db '.dump' > grafana_dump.sql
```

Future implementation is tracked in:
[Implement Grafana dashboard and alarms backup](#implement-grafana-dashboard-and-alarms-backup)&thinsp;🐞


## Grafana editing
This runbook describes adding new dashboards, panels and alerts in
[Grafana](#grafana)&thinsp;🔧

To add a new dashboard use this
<https://grafana.ooni.org/dashboard/new?orgId=1>

To add a new panel to an existing dashboard load the dashboard and then
click the \"Add\" button on the top.

Many dashboards use variables. For example, on
<https://grafana.ooni.org/d/l-MQSGonk/api-and-fastpath-multihost?orgId=1>
the variables `$host` and `$avgspan` are set on the top left and used in
metrics like:

    avg_over_time(netdata_disk_backlog_milliseconds_average{instance="$host:19999"}[$avgspan])


### Managing Grafana alert rules
Alert rules can be listed at <https://grafana.ooni.org/alerting/list>

> **note**
> The list also shows which alerts are currently alarming, if any.

Click the arrow on the left to expand each alerting rule.

The list shows:

![editing_alerts](../../../assets/images-backend/grafana_alerts_editing.png)

> **note**
> When creating alerts it can be useful to add full URLs linking to
> dashboards, runbooks etc.

To stop notifications create a \"silence\" either:

1.  by further expanding an alert rule (see below) and clicking the
    \"Silence\" button

2.  by inputting it in <https://grafana.ooni.org/alerting/silences>

Screenshot:

![adding_silence](../../../assets/images-backend/grafana_alerts_silence.png)

Additionally, the \"Show state history\" button is useful especially
with flapping alerts.


### Adding new fingerprints
This is performed on <https://github.com/ooni/blocking-fingerprints>

Updates are fetched automatically by
[Fingerprint updater](#fingerprint-updater)&thinsp;⚙

Also see [Fingerprint updater dashboard](#fingerprint-updater-dashboard)&thinsp;📊.


### Backend code changes
This runbook describes making changes to backend components and
deploying them.

Summary of the steps:

1.  Check out the backend repository.

2.  Create a dedicated branch.

3.  Update `debian/changelog` in the component you want to monify. See
    [Package versioning](#package-versioning)&thinsp;💡 for details.

4.  Run unit/functional/integ tests as needed.

5.  Create a pull request.

6.  Ensure the CI workflows are successful.

7.  Deploy the package on the testbed [ams-pg-test.ooni.org](#ams-pg-test.ooni.org)&thinsp;🖥
    and verify the change works as intended.

8.  Add a comment the PR with the deployed version and stage.

9.  Wait for the PR to be approved.

10. Deploy the package to production on
    [backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥. Ensure it is the same version
    that has been used on the testbed. See [API runbook](#api-runbook)&thinsp;📒 for
    deployment steps.

11. Add a comment the PR with the deployed version and stage, then merge
    the PR.

When introducing new metrics:

1.  Create [Grafana](#grafana)&thinsp;🔧 dashboards, alerts and
    [Jupyter Notebook](#jupyter-notebook)&thinsp;🔧 and link them in the PR.

2.  Collect and analize metrics and logs from the testbed stages before
    deploying to production.

3.  Test alarming by simulating incidents.
### Backend component deployment
This runbook provides general steps to deploy backend components on
production hosts.

Review the package changelog and the related pull request.

The amount of testing and monitoring required depends on:

1.  the impact of possible bugs in terms of number of users affected and
    consequences

2.  the level of risk involved in rolling back the change, if needed

3.  the complexity of the change and the risk of unforeseen impact

Monitor the [API and fastpath](#api-and-fastpath)&thinsp;📊 and dedicated . Review past
weeks for any anomaly before starting a deployment.

Ensure that either the database schema is consistent with the new
deployment by creating tables and columns manually, or that the new
codebase is automatically updating the database.

Quickly check past logs.

Follow logs with:

``` bash
sudo journalctl -f --no-hostname
```

While monitoring the logs, deploy the package using the
[The deployer tool](#the-deployer-tool)&thinsp;🔧 tool. (Details on the tool subchapter)


### API runbook
This runbook describes making changes to the [API](#api)&thinsp;⚙ and
deploying it.

Follow [Backend code changes](#backend-code-changes)&thinsp;📒 and
[Backend component deployment](#backend-component-deployment)&thinsp;📒.

In addition, monitor logs from Nginx and API focusing on HTTP errors and
failing SQL queries.

Manually check [Explorer](#explorer)&thinsp;🖱 and other
[Public and private web UIs](#public-and-private-web-uis)&thinsp;💡 as needed.


#### Managing feature flags
To change feature flags in the API a simple pull request like
<https://github.com/ooni/backend/pull/776> is enough.

Follow [Backend code changes](#backend-code-changes)&thinsp;📒 and deploy it after
basic testing on [ams-pg-test.ooni.org](#ams-pg-test.ooni.org)&thinsp;🖥.


### Running database queries
This subsection describes how to run queries against
[ClickHouse](#clickhouse)&thinsp;⚙. You can run queries from
[Jupyter Notebook](#jupyter-notebook)&thinsp;🔧 or from the CLI:

```bash
    ssh <backend_host>
    $ clickhouse-client
```

Prefer using the default user when possible. To log in as admin:

```bash
    $ clickhouse-client -u admin --password <redacted>
```

> **note**
> Heavy queries can impact the production database. When in doubt run them
> on the CLI interface in order to terminate them using CTRL-C if needed.

> **warning**
> ClickHouse is not transactional! Always test queries that mutate schemas
> or data on testbeds like [ams-pg-test.ooni.org](#ams-pg-test.ooni.org)&thinsp;🖥

For long running queries see the use of timeouts in
[Fastpath deduplication](#fastpath-deduplication)&thinsp;📒

Also see [Dropping tables](#dropping-tables)&thinsp;📒,
[Investigating table sizes](#investigating-table-sizes)&thinsp;📒


#### Modifying the fastpath table
This runbook show an example of changing the contents of the
[fastpath table](#fastpath-table)&thinsp;⛁ by running a \"mutation\" query.

> **warning**
> This method creates changes that cannot be reproduced by external
> researchers by [Reprocessing measurements](#reprocessing-measurements)&thinsp;📒. See
> [Reproducibility](#reproducibility)&thinsp;💡

In this example [Signal test](#signal-test)&thinsp;Ⓣ measurements are being
flagged as failed due to <https://github.com/ooni/probe/issues/2627>

Summarize affected measurements with:

``` sql
SELECT test_version, msm_failure, count()
FROM fastpath
WHERE test_name = 'signal' AND measurement_start_time > '2023-11-06T16:00:00'
GROUP BY msm_failure, test_version
ORDER BY test_version ASC
```

> **important**
> `ALTER TABLE …​ UPDATE` starts a
> [mutation](https://clickhouse.com/docs/en/sql-reference/statements/alter#mutations)
> that runs in background.

Check for any running or stuck mutation:

``` sql
SELECT * FROM system.mutations WHERE is_done != 1
```

Start the mutation:

``` sql
ALTER TABLE fastpath
UPDATE
  msm_failure = 't',
  anomaly = 'f',
  scores = '{"blocking_general":0.0,"blocking_global":0.0,"blocking_country":0.0,"blocking_isp":0.0,"blocking_local":0.0,"accuracy":0.0,"msg":"bad test_version"}'
WHERE test_name = 'signal'
AND measurement_start_time > '2023-11-06T16:00:00'
AND msm_failure = 'f'
```

Run the previous `SELECT` queries to monitor the mutation and its
outcome.


### Updating tor targets
See [Tor targets](#tor-targets)&thinsp;🐝 for a general description.

Review the [Ansible](#ansible)&thinsp;🔧 chapter. Checkout the repository and
update the file `ansible/roles/ooni-backend/templates/tor_targets.json`

Commit the changes and deploy as usual:

    ./play deploy-backend.yml --diff -l ams-pg-test.ooni.org -t api -C
    ./play deploy-backend.yml --diff -l ams-pg-test.ooni.org -t api

Test the updated configuration, then:

    ./play deploy-backend.yml --diff -l backend-fsn.ooni.org -t api -C
    ./play deploy-backend.yml --diff -l backend-fsn.ooni.org -t api

git-push the changes.

Implements [Document Tor targets](#document-tor-targets)&thinsp;🐞


### Creating admin API accounts
See [Auth](#auth)&thinsp;🐝 for a description of the API entry points related
to account management.

The API provides entry points to:

 * [get role](https://api.ooni.io/apidocs/#/default/get_api_v1_get_account_role__email_address_)

 * [set role](https://api.ooni.io/apidocs/#/default/post_api_v1_set_account_role).

The latter is implemented
[here](https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/api/ooniapi/auth.py#L437).

> **important**
> The default value for API accounts is `user`. For such accounts there is
> no need for a record in the `accounts` table.

To change roles it is required to be authenticated and have a role as
`admin`.

It is also possible to create or update roles by running SQL queries
directly on [ClickHouse](#clickhouse)&thinsp;⚙. This can be necessary to
create the initial `admin` account on a new deployment stage.

A quick way to identify the account ID an user is to extract logs from
the [API](#api)&thinsp;⚙ either from the backend host or using
[Logs from FSN notebook](#logs-from-fsn-notebook)&thinsp;📔

```bash
sudo journalctl --since '5 min ago' -u ooni-api | grep 'SELECT role FROM accounts WHERE account_id' -C5
```

Example output:

    Nov 09 16:03:00 backend-fsn ooni-api[1763457]: DEBUG Query: SELECT role FROM accounts WHERE account_id = '<redacted>'

Then on the database test host:

```bash
clickhouse-client
```

Then in the ClickHouse shell insert a record to give\`admin\` role to
the user. See [Running database queries](#running-database-queries)&thinsp;📒:

```sql
INSERT INTO accounts (account_id, role) VALUES ('<redacted>', 'admin')
```

`accounts` is an EmbeddedRocksDB table with `account_id` as primary key.
No record deduplication is necessary.

To access the new role the user has to log out from web UIs and login
again.

> **important**
> Account IDs are not the same across test and production instances.

This is due to the use of a configuration variable
`ACCOUNT_ID_HASHING_KEY` in the hashing of the email address. The
parameter is read from the API configuration file. The values are
different across deployment stages as a security feature.


### Fastpath runbook

#### Fastpath code changes and deployment
Review [Backend code changes](#backend-code-changes)&thinsp;📒 and
[Backend component deployment](#backend-component-deployment)&thinsp;📒 for changes and deployment of the
backend stack in general.

Also see [Modifying the fastpath table](#modifying-the-fastpath-table)&thinsp;📒

In addition, monitor logs and [Grafana dashboards](#grafana-dashboards)&thinsp;💡
focusing on changes in incoming measurements.

You can use the [The deployer tool](#the-deployer-tool)&thinsp;🔧 tool to perform
deployment and rollbacks of the [Fastpath](#fastpath)&thinsp;⚙.

> **important**
> the fastpath is configured **not** to restart automatically during
> deployment.

Always monitor logs and restart it as needed:

```bash
sudo systemctl restart fastpath
```


#### Fastpath manual deployment
Sometimes it can be useful to run APT directly:

```bash
ssh <host>
sudo apt-get update
apt-cache show fastpath | grep Ver | head -n5
sudo apt-get install fastpath=<version>
```


#### Reprocessing measurements
Reprocess old measurement by running the fastpath manually. This can be
done without shutting down the fastpath instance running on live
measurements.

You can run the fastpath as root or using the fastpath user. Both users
are able to read the configuration file under `/etc/ooni`. The fastpath
will download [Postcans](#postcans)&thinsp;💡 in the local directory.

`fastpath -h` generates:

    usage:
    OONI Fastpath

    See README.adoc

     [-h] [--start-day START_DAY] [--end-day END_DAY]
                                             [--devel] [--noapi] [--stdout] [--debug]
                                             [--db-uri DB_URI]
                                             [--clickhouse-url CLICKHOUSE_URL] [--update]
                                             [--stop-after STOP_AFTER] [--no-write-to-db]
                                             [--keep-s3-cache] [--ccs CCS]
                                             [--testnames TESTNAMES]

    options:
      -h, --help            show this help message and exit
      --start-day START_DAY
      --end-day END_DAY
      --devel               Devel mode
      --noapi               Process measurements from S3 and do not start API feeder
      --stdout              Log to stdout
      --debug               Log at debug level
      --clickhouse-url CLICKHOUSE_URL
                            ClickHouse url
      --stop-after STOP_AFTER
                            Stop after feeding N measurements from S3
      --no-write-to-db      Do not insert measurement in database
      --ccs CCS             Filter comma-separated CCs when feeding from S3
      --testnames TESTNAMES
                            Filter comma-separated test names when feeding from S3 (without
                            underscores)

To run the fastpath manually use:

    ssh <host>
    sudo sudo -u fastpath /bin/bash

    fastpath --help
    fastpath --start-day 2023-08-14 --end-day 2023-08-19 --noapi --stdout

The `--no-write-to-db` option can be useful for testing.

The `--ccs` and `--testnames` flags are useful to selectively reprocess
measurements.

After reprocessing measurements it's recommended to manually deduplicate
the contents of the `fastpath` table. See
[Fastpath deduplication](#fastpath-deduplication)&thinsp;📒

> **note**
> it is possible to run multiple `fastpath` processes using
> <https://www.gnu.org/software/parallel/> with different time ranges.
> Running the reprocessing under `byobu` is recommended.

The fastpath will pull [Postcans](#postcans)&thinsp;💡 from S3. See
[Feed fastpath from JSONL](#feed-fastpath-from-jsonl)&thinsp;🐞 for possible speedup.


#### Fastpath monitoring
The fastpath pipeline can be monitored using the
[Fastpath dashboard](#dash:api_fp) and [API and fastpath](#api-and-fastpath)&thinsp;📊.

Also follow real-time process using:

    sudo journalctl -f -u fastpath


### Android probe release runbook
This runbook is meant to help coordinate Android probe releases between
the probe and backend developers and public announcements. It does not
contain detailed instructions for individual components.

Also see the [Measurement drop runbook](#measurement-drop-tutorial)&thinsp;📒.


Roles: \@probe, \@backend, \@media


#### Android pre-release
\@probe: drive the process involving the other teams as needed. Create
calendar events to track the next steps. Run the probe checklist
<https://docs.google.com/document/d/1S6X5DqVd8YzlBLRvMFa4RR6aGQs8HSXfz8oGkKoKwnA/edit>

\@backend: review
<https://jupyter.ooni.org/view/notebooks/jupycron/autorun_android_probe_release.html>
and
<https://grafana.ooni.org/d/l-MQSGonk/api-and-fastpath-multihost?orgId=1&refresh=5s&var-avgspan=8h&var-host=backend-fsn.ooni.org&from=now-30d&to=now>
for long-term trends


#### Android release
\@probe: release the probe for early adopters

\@backend: monitor
<https://jupyter.ooni.org/view/notebooks/jupycron/autorun_android_probe_release.html>
frequently during the first 24h and report any drop on
[Slack](#slack)&thinsp;🔧

\@probe: wait at least 24h then release the probe for all users

\@backend: monitor
<https://jupyter.ooni.org/view/notebooks/jupycron/autorun_android_probe_release.html>
daily for 14 days and report any drop on [Slack](#slack)&thinsp;🔧

\@probe: wait at least 24h then poke \@media to announce the release

(<https://github.com/ooni/backend/wiki/Runbooks:-Android-Probe-Release>


### CLI probe release runbook
This runbook is meant to help coordinate CLI probe releases between the
probe and backend developers and public announcements. It does not
contain detailed instructions for individual components.

Roles: \@probe, \@backend, \@media


#### CLI pre-release
\@probe: drive the process involving the other teams as needed. Create
calendar events to track the next steps. Run the probe checklist and
review the CI.

\@backend: review
\[jupyter\](<https://jupyter.ooni.org/view/notebooks/jupycron/autorun_cli_probe_release.html>)
and
\[grafana\](<https://grafana.ooni.org/d/l-MQSGonk/api-and-fastpath-multihost?orgId=1&refresh=5s&var-avgspan=8h&var-host=backend-fsn.ooni.org&from=now-30d&to=now>)
for long-term trends


#### CLI release
\@probe: release the probe for early adopters

\@backend: monitor
\[jupyter\](<https://jupyter.ooni.org/view/notebooks/jupycron/autorun_cli_probe_release.html>)
frequently during the first 24h and report any drop on
[Slack](#slack)&thinsp;🔧

\@probe: wait at least 24h then release the probe for all users

\@backend: monitor
\[jupyter\](<https://jupyter.ooni.org/view/notebooks/jupycron/autorun_cli_probe_release.html>)
daily for 14 days and report any drop on [Slack](#slack)&thinsp;🔧

\@probe: wait at least 24h then poke \@media to announce the release


### Investigating heavy aggregation queries runbook
In the following scenario the [Aggregation and MAT](#aggregation-and-mat)&thinsp;🐝 API is
experiencing query timeouts impacting users.

Reproduce the issue by setting a large enough time span on the MAT,
e.g.:
<https://explorer.ooni.org/chart/mat?test_name=web_connectivity&axis_x=measurement_start_day&since=2023-10-15&until=2023-11-15&time_grain=day>

Click on the link to JSON, e.g.
<https://api.ooni.io/api/v1/aggregation?test_name=web_connectivity&axis_x=measurement_start_day&since=2023-01-01&until=2023-11-15&time_grain=day>

Review the [backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥 metrics on
<https://grafana.ooni.org/d/M1rOa7CWz/netdata?orgId=1&var-instance=backend-fsn.ooni.org:19999>
(see [Netdata-specific dashboard](#netdata-specific-dashboard)&thinsp;📊 for details)

Also review the [API and fastpath](#api-and-fastpath)&thinsp;📊 dashboard, looking at
CPU load, disk I/O, query time, measurement flow.

Also see [Aggregation cache monitoring](#aggregation-cache-monitoring)&thinsp;🐍

Refresh and review the charts on the [ClickHouse queries notebook](#clickhouse-queries-notebook)&thinsp;📔.

In this instance frequent calls to the aggregation API are found.

Review the summary of the API quotas. See
[Calling the API manually](#calling-the-api-manually)&thinsp;📒 for details:

    $ http https://api.ooni.io/api/_/quotas_summary Authorization:'Bearer <mytoken>'

Log on [backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥 and review the logs:

    backend-fsn:~$ sudo journalctl --since '5 min ago'

Summarize the subnets calling the API:

    backend-fsn:~$ sudo journalctl --since '5 hour ago' -u ooni-api -u nginx | grep aggreg | cut -d' ' -f 8 | sort | uniq -c | sort -nr | head

    807 <redacted subnet>
    112 <redacted subnet>
     92 <redacted subnet>
     38 <redacted subnet>
     16 <redacted subnet>
     15 <redacted subnet>
     11 <redacted subnet>
     11 <redacted subnet>
     10 <redacted subnet>

To block IP addresses or subnets see [Nginx](#nginx)&thinsp;⚙ or
[HaProxy](#haproxy)&thinsp;⚙, then configure the required file in
[Ansible](#ansible)&thinsp;🔧 and deploy.

Also see [Limiting scraping](#limiting-scraping)&thinsp;📒.


### Aggregation cache monitoring
To monitor cache hit/miss ratio using StatsD metrics the following
script can be run as needed.

See [Metrics list](#metrics-list)&thinsp;💡.

``` python
import subprocess

import statsd
metrics = statsd.StatsClient('localhost', 8125)

def main():
    cmd = "sudo journalctl --since '5 min ago' -u nginx | grep 'GET /api/v1/aggregation' | cut -d ' ' -f 10 | sort | uniq -c"
    out = subprocess.check_output(cmd, shell=True)
    for line in out.splitlines():
        cnt, name = line.strip().split()
        name = name.decode()
        metrics.gauge(f"nginx_aggregation_cache_{name}", int(cnt))

if __name__ == '__main__':
    main()
```


### Limiting scraping
Aggressive bots and scrapers can be limited using a combination of
methods. Listed below ordered starting from the most user-friendly:

1.  Reduce the impact on the API (CPU, disk I/O, memory usage) by
    caching the results.

2.  [Rate limiting and quotas](#rate-limiting-and-quotas)&thinsp;🐝 already built in the API. It
    might need lowering of the quotas.

3.  Adding API entry points to [Robots.txt](#robots.txt)&thinsp;🐝

4.  Adding specific `User-Agent` entries to [Robots.txt](#robots.txt)&thinsp;🐝

5.  Blocking IP addresses or subnets in the [Nginx](#nginx)&thinsp;⚙ or
    [HaProxy](#haproxy)&thinsp;⚙ configuration files

To add caching to the API or increase the expiration times:

1.  Identify API calls that cause significant load. [Nginx](#nginx)&thinsp;⚙
    is configured to log timing information for each HTTP request. See
    [Logs investigation notebook](#logs-investigation-notebook)&thinsp;📔 for examples. Also see
    [Logs from FSN notebook](#logs-from-fsn-notebook)&thinsp;📔 and
    [ClickHouse instance for logs](#clickhouse-instance-for-logs)&thinsp;⚙. Additionally,
    [Aggregation cache monitoring](#aggregation-cache-monitoring)&thinsp;🐍 can be tweaked for the present use-case.

2.  Implement caching or increase expiration times across the API
    codebase. See [API cache](#api-cache)&thinsp;💡 and
    [Purging Nginx cache](#purging-nginx-cache)&thinsp;📒.

3.  Monitor the improvement in terms of cache hit VS cache miss ratio.

> **important**
> Caching can be applied selectively for API requests that return rapidly
> changing data VS old, stable data. See [Aggregation and MAT](#aggregation-and-mat)&thinsp;🐝
> for an example.

To update the quotas edit the API here
<https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/api/ooniapi/app.py#L187>
and deploy as usual.

To update the `robots.txt` entry point see [Robots.txt](#robots.txt)&thinsp;🐝 and
edit the API here
<https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/api/ooniapi/pages/>*init*.py#L124
and deploy as usual

To block IP addresses or subnets see [Nginx](#nginx)&thinsp;⚙ or
[HaProxy](#haproxy)&thinsp;⚙, then configure the required file in
[Ansible](#ansible)&thinsp;🔧 and deploy.


### Calling the API manually
To make HTTP calls to the API manually you'll need to extact a JWT from
the browser, sometimes with admin rights.

In Firefox, authenticate against <https://test-lists.ooni.org/> , then
open Inspect \>\> Storage \>\> Local Storage \>\> Find
`{"token": "<mytoken>"}`

Extract the token ascii-encoded string without braces nor quotes.

Call the API using [httpie](https://httpie.io/) with:

    $ http https://api.ooni.io/<path> Authorization:'Bearer <mytoken>'

E.g.:

    $ http https://api.ooni.io/api/_/quotas_summary Authorization:'Bearer <mytoken>'

> **note**
> Do not leave whitespaces after \"Authorization:\"


### Build, deploy, rollback

Host deployments are done with the
[sysadmin repo](https://github.com/ooni/sysadmin)

For component updates a deployment pipeline is used:

Look at the \[Status
dashboard\](<https://github.com/ooni/backend/wiki/Backend>) - be aware
of badge image caching


### The deployer tool
Deployments can be performed with a tool that acts as a frontend for
APT. It implements a simple Continuous Delivery workflow from CLI. It
does not require running a centralized CD pipeline server (e.g. like
<https://www.gocd.org/>)

The tool is hosted on the backend repository together with its
configuration file for simplicity:
<https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/deployer>

At start time it traverses the path from the current working directory
back to root until it finds a configuration file named deployer.ini This
allows using different deployment pipelines stored in configuration
files across different repositories and subdirectories.

The tool connects to the hosts to perform deployments and requires sudo
rights. It installs Debian packages from repositories already configured
on the hosts.

It runs `apt-get update` and then `apt-get install …​` to update or
rollback packages. By design, it does not interfere with manual
execution of apt-get or through tools like [Ansible](#ansible)&thinsp;🔧.
This means operators can log on a host to do manual upgrade or rollback
of packages without breaking the deployer tool.

The tool depends only on the `python3-apt` package.

Here is a configuration file example, with comments:

``` ini
[environment]
## Location on the path where SVG badges are stored
badges_path = /var/www/package_badges


## List of packages that are handled by the deployer, space separated
deb_packages = ooni-api fastpath analysis detector


## List of deployment stage names, space separated, from the least to the most critical
stages = test hel prod


## For each stage a block named stage:<stage_name> is required.
## The block lists the stage hosts.


## Example of an unused stage (not list under stages)
[stage:alpha]
hosts = localhost

[stage:test]
hosts = ams-pg-test.ooni.org

[stage:hel]
hosts = backend-hel.ooni.org

[stage:prod]
hosts = backend-fsn.ooni.org
```

By running the tool without any argument it will connect to the hosts
from the configuration file and print a summary of the installed
packages, for example:

``` bash
$ deployer

     Package               test                   prod
ooni-api               1.0.79~pr751-194       1.0.79~pr751-194
fastpath               0.81~pr748-191     ►►  0.77~pr705-119
analysis               1.9~pr659-61       ⚠   1.10~pr692-102
detector               0.3~pr651-98           0.3~pr651-98
```

The green arrows between two package versions indicates that the version
on the left side is higher than the one on the right side. This means
that a rollout is pending. In the example the fastpath package on the
\"prod\" stage can be updated.

A red warning sign indicates that the version on the right side is
higher than the one on the left side. During a typical continuous
deployment workflow version numbers should always increment The rollout
should go from left to right, aka from the least critical stage to the
most critical stage.

Deploy/rollback a given version on the \"test\" stage:

``` bash
./deployer deploy ooni-api test 0.6~pr194-147
```

Deploy latest build on the first stage:

``` bash
./deployer deploy ooni-api
```

Deploy latest build on a given stage. This usage is not recommended as
it deploys the latest build regardless of what is currently running on
previous stages.

``` bash
./deployer deploy ooni-api prod
```

The deployer tool can also generate SVG badges that can then served by
[Nginx](#nginx)&thinsp;⚙ or copied elsewhere to create a status dashboard.

Example:

![badge](../../../assets/images-backend/badge.png)

Update all badges with:

``` bash
./deployer refresh_badges
```


### Adding new tests
This runbook describes how to add support for a new test in the
[Fastpath](#fastpath)&thinsp;⚙.

Review [Backend code changes](#backend-code-changes)&thinsp;📒, then update
[fastpath core](https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/fastpath/fastpath/core.py)
to add a scoring function.

See for example `def score_torsf(msm: dict) → dict:`

Also add an `if` block to the `def score_measurement(msm: dict) → dict:`
function to call the newly created function.

Finish by adding a new test to the `score_measurement` function and
adding relevant integration tests.

Run the integration tests locally.

Update the
[api](https://github.rom/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/api/ooniapi/measurements.py#L491)
if needed.

Deploy on [ams-pg-test.ooni.org](#ams-pg-test.ooni.org)&thinsp;🖥 and run end-to-end tests
using real probes.


### Adding support for a new test key
This runbook describes how to modify the [Fastpath](#fastpath)&thinsp;⚙
and the [API](#api)&thinsp;⚙ to extract, process, store and publish a new measurement
field.

Start with adding a new column to the [fastpath table](#fastpath-table)&thinsp;⛁
by following [Adding a new column to the fastpath](#adding-a-new-column-to-the-fastpath)&thinsp;📒.

Add the column to the local ClickHouse instance used for tests and
[ams-pg-test.ooni.org](#ams-pg-test.ooni.org)&thinsp;🖥.

Update <https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/api/tests/integ/clickhouse_1_schema.sql> as described in
[Continuous Deployment: Database schema changes](#continuous-deployment:-database-schema-changes)&thinsp;💡

Add support for the new field in the fastpath `core.py` and `db.py` modules
and related tests.
See https://github.com/ooni/backend/pull/682 for a comprehensive example.

Run tests locally, then open a draft pull request and ensure the CI tests are
running successfully.

If needed, the current pull request can be reviewed and deployed without modifying the API to expose the new column. This allows processing data sooner while the API is still being worked on.

Add support for the new column in the API. The change depends on where and how the
new value is to be published.
See <https://github.com/ooni/backend/commit/ae2097498ec4d6a271d8cdca9d68bd277a7ac19d#diff-4a1608b389874f2c35c64297e9c676dffafd49b9ba80e495a703ba51d2ebd2bbL359> for a generic example of updating an SQL query in the API and updating related tests.

Deploy the changes on test and pre-production stages after creating the new column in the database.
See [The deployer tool](#the-deployer-tool)&thinsp;🔧 for details.

Perform end-to-end tests with real probes and [Public and private web UIs](#public-and-private-web-uis)&thinsp;💡 as needed.

Complete the pull request and deploy to production.


## Increasing the disk size on a dedicated host

Below are some notes on how to resize the disks when a new drive is added to
our dedicated hosts:

```
fdisk /dev/nvme3n1
# create gpt partition table and new RAID 5 (label 42) partition using the CLI
mdadm --manage /dev/md3 --add /dev/nvme3n1p1
cat /proc/mdstat
# Take note of the volume count (4) and validate that nvme3n1p1 is marked as spare ("S")
mdadm --grow --raid-devices=4 /dev/md3
```

```
# resize2fs /dev/md3
# df -h | grep md3
/dev/md3        2.6T  1.2T  1.3T  48% /
```

## Replicating MergeTree tables

Notes on how to go about converting a MergeTree family table to a replicated table, while minimizing downtime.

See the following links for more information:

- https://kb.altinity.com/altinity-kb-setup-and-maintenance/altinity-kb-converting-mergetree-to-replicated/
- https://clickhouse.com/docs/en/operations/system-tables/replicas
- https://clickhouse.com/docs/en/architecture/replication#verify-that-clickhouse-keeper-is-running
- https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/replication
- https://clickhouse.com/docs/en/operations/server-configuration-parameters/settings

### Workflow

You should first create the replicated database cluster following the
instructions at the [clickhouse docs](https://clickhouse.com/docs/en/architecture/replication).

The ooni-devops repo has a role called `oonidata_clickhouse` that does that by using the [idealista.clickhouse_role](https://github.com/idealista/clickhouse_role).

Once the cluster is created you can proceed with creating a DATABASE on the cluster by running:

```
CREATE DATABASE ooni ON CLUSTER oonidata_cluster
```

There are now a few options to go about doing this:

1. You just create the new replicated tables and perform a copy into the destination database by running on the source database the following:

```
INSERT INTO FUNCTION
remote('destination-database.ooni.nu', 'obs_web', 'USER', 'PASSWORD')
SELECT * from obs_web
```

This will require duplicating the data and might not be feasible.

2. If you already have all the data setup on one host and you just want to convert the database into a replicate one, you can do the following:

We assume there are 2 tables: `obs_web_bak` (which is the source table) and
`obs_web` which is the destination table. We also assume a single shard and
multiple replicas.

First create the destination replicated table. To retrieve the table create query you can run:

```sql
select create_table_query
from system.tables
where database = 'default' and table = 'obs_web'
```

You should then modify the table to make use of the `ReplicateReplacingMergeTree` engine:

```sql
CREATE TABLE ooni.obs_web (`measurement_uid` String, `observation_idx` UInt16, `input` Nullable(String), `report_id` String, `measurement_start_time` DateTime64(3, 'UTC'), `software_name` String, `software_version` String, `test_name` String, `test_version` String, `bucket_date` String, `probe_asn` UInt32, `probe_cc` String, `probe_as_org_name` String, `probe_as_cc` String, `probe_as_name` String, `network_type` String, `platform` String, `origin` String, `engine_name` String, `engine_version` String, `architecture` String, `resolver_ip` String, `resolver_asn` UInt32, `resolver_cc` String, `resolver_as_org_name` String, `resolver_as_cc` String, `resolver_is_scrubbed` UInt8, `resolver_asn_probe` UInt32, `resolver_as_org_name_probe` String, `created_at` Nullable(DateTime('UTC')), `target_id` Nullable(String), `hostname` Nullable(String), `transaction_id` Nullable(UInt16), `ip` Nullable(String), `port` Nullable(UInt16), `ip_asn` Nullable(UInt32), `ip_as_org_name` Nullable(String), `ip_as_cc` Nullable(String), `ip_cc` Nullable(String), `ip_is_bogon` Nullable(UInt8), `dns_query_type` Nullable(String), `dns_failure` Nullable(String), `dns_engine` Nullable(String), `dns_engine_resolver_address` Nullable(String), `dns_answer_type` Nullable(String), `dns_answer` Nullable(String), `dns_answer_asn` Nullable(UInt32), `dns_answer_as_org_name` Nullable(String), `dns_t` Nullable(Float64), `tcp_failure` Nullable(String), `tcp_success` Nullable(UInt8), `tcp_t` Nullable(Float64), `tls_failure` Nullable(String), `tls_server_name` Nullable(String), `tls_version` Nullable(String), `tls_cipher_suite` Nullable(String), `tls_is_certificate_valid` Nullable(UInt8), `tls_end_entity_certificate_fingerprint` Nullable(String), `tls_end_entity_certificate_subject` Nullable(String), `tls_end_entity_certificate_subject_common_name` Nullable(String), `tls_end_entity_certificate_issuer` Nullable(String), `tls_end_entity_certificate_issuer_common_name` Nullable(String), `tls_end_entity_certificate_san_list` Array(String), `tls_end_entity_certificate_not_valid_after` Nullable(DateTime64(3, 'UTC')), `tls_end_entity_certificate_not_valid_before` Nullable(DateTime64(3, 'UTC')), `tls_certificate_chain_length` Nullable(UInt16), `tls_certificate_chain_fingerprints` Array(String), `tls_handshake_read_count` Nullable(UInt16), `tls_handshake_write_count` Nullable(UInt16), `tls_handshake_read_bytes` Nullable(UInt32), `tls_handshake_write_bytes` Nullable(UInt32), `tls_handshake_last_operation` Nullable(String), `tls_handshake_time` Nullable(Float64), `tls_t` Nullable(Float64), `http_request_url` Nullable(String), `http_network` Nullable(String), `http_alpn` Nullable(String), `http_failure` Nullable(String), `http_request_body_length` Nullable(UInt32), `http_request_method` Nullable(String), `http_runtime` Nullable(Float64), `http_response_body_length` Nullable(Int32), `http_response_body_is_truncated` Nullable(UInt8), `http_response_body_sha1` Nullable(String), `http_response_status_code` Nullable(UInt16), `http_response_header_location` Nullable(String), `http_response_header_server` Nullable(String), `http_request_redirect_from` Nullable(String), `http_request_body_is_truncated` Nullable(UInt8), `http_t` Nullable(Float64), `probe_analysis` Nullable(String))
ENGINE = ReplicatedReplacingMergeTree(
'/clickhouse/{cluster}/tables/{database}/{table}/{shard}',
'{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time, probe_cc, probe_asn) SETTINGS index_granularity = 8192
```

Check all the partitions that exist for the source table and produce ALTER queries to map them from the source to the destination:

```sql
SELECT DISTINCT 'ALTER TABLE ooni.obs_web ATTACH PARTITION ID \'' || partition_id || '\' FROM obs_web_bak;' from system.parts WHERE table = 'obs_web_bak' AND active;
```

While you are running the following, you should stop all merges by running:

```sql
SYSTEM STOP MERGES;
```

This can then be scripted like so:

```sh
clickhouse-client -q "SELECT DISTINCT 'ALTER TABLE ooni.obs_web ATTACH PARTITION ID \'' || partition_id || '\' FROM obs_web_bak;' from system.parts WHERE table = 'obs_web_bak' format TabSeparatedRaw" | clickhouse-client -u write --password XXXX -mn
```

You will now have a replicated table existing on one of the replicas.

Then you shall for each other replica in the set manually create the table, but this time pass in it explicitly the zookeeper path.

You can get the zookeeper path by running the following on the first replica you have setup

```sql
SELECT zookeeper_path FROM system.replicas WHERE table = 'obs_web';
```

For each replica you will then have to create the tables like so:

```sql
CREATE TABLE ooni.obs_web (`measurement_uid` String, `observation_idx` UInt16, `input` Nullable(String), `report_id` String, `measurement_start_time` DateTime64(3, 'UTC'), `software_name` String, `software_version` String, `test_name` String, `test_version` String, `bucket_date` String, `probe_asn` UInt32, `probe_cc` String, `probe_as_org_name` String, `probe_as_cc` String, `probe_as_name` String, `network_type` String, `platform` String, `origin` String, `engine_name` String, `engine_version` String, `architecture` String, `resolver_ip` String, `resolver_asn` UInt32, `resolver_cc` String, `resolver_as_org_name` String, `resolver_as_cc` String, `resolver_is_scrubbed` UInt8, `resolver_asn_probe` UInt32, `resolver_as_org_name_probe` String, `created_at` Nullable(DateTime('UTC')), `target_id` Nullable(String), `hostname` Nullable(String), `transaction_id` Nullable(UInt16), `ip` Nullable(String), `port` Nullable(UInt16), `ip_asn` Nullable(UInt32), `ip_as_org_name` Nullable(String), `ip_as_cc` Nullable(String), `ip_cc` Nullable(String), `ip_is_bogon` Nullable(UInt8), `dns_query_type` Nullable(String), `dns_failure` Nullable(String), `dns_engine` Nullable(String), `dns_engine_resolver_address` Nullable(String), `dns_answer_type` Nullable(String), `dns_answer` Nullable(String), `dns_answer_asn` Nullable(UInt32), `dns_answer_as_org_name` Nullable(String), `dns_t` Nullable(Float64), `tcp_failure` Nullable(String), `tcp_success` Nullable(UInt8), `tcp_t` Nullable(Float64), `tls_failure` Nullable(String), `tls_server_name` Nullable(String), `tls_version` Nullable(String), `tls_cipher_suite` Nullable(String), `tls_is_certificate_valid` Nullable(UInt8), `tls_end_entity_certificate_fingerprint` Nullable(String), `tls_end_entity_certificate_subject` Nullable(String), `tls_end_entity_certificate_subject_common_name` Nullable(String), `tls_end_entity_certificate_issuer` Nullable(String), `tls_end_entity_certificate_issuer_common_name` Nullable(String), `tls_end_entity_certificate_san_list` Array(String), `tls_end_entity_certificate_not_valid_after` Nullable(DateTime64(3, 'UTC')), `tls_end_entity_certificate_not_valid_before` Nullable(DateTime64(3, 'UTC')), `tls_certificate_chain_length` Nullable(UInt16), `tls_certificate_chain_fingerprints` Array(String), `tls_handshake_read_count` Nullable(UInt16), `tls_handshake_write_count` Nullable(UInt16), `tls_handshake_read_bytes` Nullable(UInt32), `tls_handshake_write_bytes` Nullable(UInt32), `tls_handshake_last_operation` Nullable(String), `tls_handshake_time` Nullable(Float64), `tls_t` Nullable(Float64), `http_request_url` Nullable(String), `http_network` Nullable(String), `http_alpn` Nullable(String), `http_failure` Nullable(String), `http_request_body_length` Nullable(UInt32), `http_request_method` Nullable(String), `http_runtime` Nullable(Float64), `http_response_body_length` Nullable(Int32), `http_response_body_is_truncated` Nullable(UInt8), `http_response_body_sha1` Nullable(String), `http_response_status_code` Nullable(UInt16), `http_response_header_location` Nullable(String), `http_response_header_server` Nullable(String), `http_request_redirect_from` Nullable(String), `http_request_body_is_truncated` Nullable(UInt8), `http_t` Nullable(Float64), `probe_analysis` Nullable(String))
ENGINE = ReplicatedReplacingMergeTree(
'/clickhouse/oonidata_cluster/tables/ooni/obs_web/01',
'{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx)
ORDER BY (measurement_uid, observation_idx, measurement_start_time, probe_cc, probe_asn) SETTINGS index_granularity = 8192
```

You will then have to manually copy the data over to the destination replica from the source.

The data lives inside of `/var/lib/clickhouse/data/{database_name}/{table_name}`

Once the data has been copied over you should now have replicated the data and you can resume merges on all database by running:

```sql
SYSTEM START MERGES;
```

### Creating tables on clusters

```sql
CREATE TABLE ooni.obs_web_ctrl ON CLUSTER oonidata_cluster
(`measurement_uid` String, `observation_idx` UInt16, `input` Nullable(String), `report_id` String, `measurement_start_time` DateTime64(3, 'UTC'), `software_name` String, `software_version` String, `test_name` String, `test_version` String, `bucket_date` String, `hostname` String, `created_at` Nullable(DateTime64(3, 'UTC')), `ip` String, `port` Nullable(UInt16), `ip_asn` Nullable(UInt32), `ip_as_org_name` Nullable(String), `ip_as_cc` Nullable(String), `ip_cc` Nullable(String), `ip_is_bogon` Nullable(UInt8), `dns_failure` Nullable(String), `dns_success` Nullable(UInt8), `tcp_failure` Nullable(String), `tcp_success` Nullable(UInt8), `tls_failure` Nullable(String), `tls_success` Nullable(UInt8), `tls_server_name` Nullable(String), `http_request_url` Nullable(String), `http_failure` Nullable(String), `http_success` Nullable(UInt8), `http_response_body_length` Nullable(Int32))
ENGINE = ReplicatedReplacingMergeTree(
'/clickhouse/{cluster}/tables/{database}/{table}/{shard}',
'{replica}'
)
PARTITION BY concat(substring(bucket_date, 1, 4), substring(bucket_date, 6, 2))
PRIMARY KEY (measurement_uid, observation_idx) ORDER BY (measurement_uid, observation_idx, measurement_start_time, hostname) SETTINGS index_granularity = 8192
```

### Adding users to notebook server

In order to add new users to the jupyterlab notebook server hosted
`notebook.ooni.org` the steps are:

1. Open a PR adding an entry to this list:
   https://github.com/ooni/devops/blob/main/ansible/host_vars/notebook1.htz-fsn.prod.ooni.nu (we need ssh key, email and username)
2. An OONI core team member will run:
```
./play deploy-bootstrap.yml -l notebook1.htz-fsn.prod.ooni.nu --diff -i inventory
```
3. An OONI core team member logs into `notebook1.htz-fsn.prod.ooni.nu` and runs:
```
sudo passwd NEWUSERNAME
```
and sets the password of the new user to a randomly generated password prefixed with the string `CHANGEME`
4. This password is sent privately to the new user and they are told to login via ssh using their key to update the password
5. This user is now able to login with the password they have chosen via https://notebook.ooni.org/

### Reprocessing data

In order to reprocess older data the steps are:

1. Update oonipipeline on the airflow host to the latest version by running the `deploy-airflow.yml` playbook:
```
./play deploy-airflow.yml --diff -i inventory
```

2. Trigger the main run task, preferrably under tmux, on the airflow host (airflow.prod.ooni.io):
```
CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main run --start-at 2025-01-01 --end-at 2025-02-01
```

3. Wait for it to converge and then verify that there are no duplicates left around by running:
```
CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main run check-duplicates --start-at 2025-01-01 --end-at 2025-02-01
```

If there are duplicate you can prune them with:
```
CONFIG_FILE=/etc/ooni/pipeline/oonipipeline-config.toml /opt/miniconda/bin/python -m oonipipeline.main run check-duplicates --start-at 2025-01-01 --end-at 2025-02-01 --optimize
```

## Adding external users to the notebooks server

Some users can request access to the notebooks server for research purposes, this way they can access the clickhouse database from a research-friendly
interface. We can provide them access by creating an account for them.

The notebook server is using the actual server users to authenticate access to the jupyter web interface. To create an user
we usually create an user within the server. The idea is:

1. Create a new user
2. Set their default password
3. Set their password to be changed on next login
4. Ask them to login one time to update the password
5. They can now log in into [notebook.ooni.org](https://notebook.ooni.org) with their new password

Then the procedure is as follows:

1. Create new user entry here in the [notebook server's host vars](https://github.com/ooni/devops/blob/main/ansible/host_vars/notebook1.htz-fsn.prod.ooni.nu):
2. Run:
  ```
  ```
