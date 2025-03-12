# Legacy Docs

**ATTENTION** this documentation speaks about topics that are still relevant, yet it may not be up to date with the currently defined best-practices or infrastructure status.

### Creating new playbooks runbook

**TODO** this needs to be rewritten to conform to the new policies


This runbook describe how to add new runbooks or modify existing runbooks to support new hosts.

When adding a new host to an existing group, if no customization is required it is enough to modify `inventory`
and insert the hostname in the same locations as its peers.

If the host requires small customization e.g. a different configuration file for the <<comp:api>>:

1. add the hostname to `inventory` as described above
2. create "custom" blocks in `tasks/main.yml` to adapt the deployment steps to the new host using the `when:` syntax.

For an example see: <https://github.com/ooni/sysadmin/blob/adb22576791baae046827c79e99b71fc825caae0/ansible/roles/ooni-backend/tasks/main.yml#L65>

NOTE: Complex `when:` rules can lower the readability of `main.yml`

When adding a new type of backend component that is different from anything already existing a new dedicated role can be created:

1. add the hostname to `inventory` as described above
2. create a new playbook e.g. `ansible/deploy-newcomponent.yml`
3. copy files from an existing role into a new `ansible/roles/newcomponent` directory:

- `ansible/roles/newcomponent/meta/main.yml`
- `ansible/roles/newcomponent/tasks/main.yml`
- `ansible/roles/newcomponent/templates/example_config_file`

4. run `./play deploy-newcomponent.yml -l newhost.ooni.org --diff -C` and review the output
5. run `./play deploy-newcomponent.yml -l newhost.ooni.org --diff` and review the output

Example: <https://github.com/ooni/sysadmin/commit/50271b9f5a8fd96dad5531c01fcfdd08bac98fe9>

TIP: To ensure playbooks are robust and idemponent it can be beneficial to develop and test tasks incrementally by running the deployment commands often.


## Test helper rotation runbook
This runbook provides hints to troubleshoot the rotation of test
helpers. In this scenario test helpers are not being rotated as expected
and their TLS certificates might be at risk of expiring.

Steps:

1.  Review [Test helpers](#comp:test_helpers), [Test helper rotation](#comp:test_helper_rotation) and [Test helpers notebook](#test-helpers-notebook)&thinsp;📔

2.  Review the charts on [Test helpers dashboard](#test-helpers-dashboard)&thinsp;📊.
    Look at different timespans:

    a.  The uptime of the test helpers should be staggered by a week
        depending on [Test helper rotation](#test-helper-rotation)&thinsp;⚙.

3.  A summary of the live and last rotated test helper can be obtained
    with:

```sql
SELECT rdn, dns_zone, name, region, draining_at FROM test_helper_instances ORDER BY name DESC LIMIT 8
```

4.  The rotation tool can be started manually. It will always pick the
    oldest host for rotation. ⚠️ Due to the propagation time of changes
    in the DNS rotating many test helpers too quickly can impact the
    probes.

    a.  Log on [backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥

    b.  Check the last run using
        `sudo systemctl status ooni-rotation.timer`

    c.  Review the logs using `sudo journalctl -u ooni-rotation`

    d.  Run `sudo systemctl restart ooni-rotation` and monitor the logs.

5.  Review the charts on [Test helpers dashboard](#test-helpers-dashboard)&thinsp;📊
    during and after the rotation.


### Test helpers failure runbook
This runbook presents a scenario where a test helper is causing probes
to fail their tests sporadically. It describes how to identify the
affected host and mitigate the issue but can also be used to investigate
other issues affecting the test helpers.

It has been chosen because such kind of incidents can impact the quality
of measurements and can be relatively difficult to troubleshoot.

For investigating glitches in the
[test helper rotation](#test-helper-rotation)&thinsp;⚙ see
[test helper rotation runbook](#test-helper-rotation-runbook)&thinsp;📒.

In this scenario either an alert has been sent to the
[#ooni-bots](#topic:oonibots) [Slack](#slack)&thinsp;🔧 channel by
the [test helper failure rate notebook](#test-helper-failure-rate-notebook)&thinsp;📔 or something
else caused the investigation.
See [Alerting](#alerting)&thinsp;💡 for details.

Steps:

1.  Review [Test helpers](#test-helpers)&thinsp;⚙

2.  Review the charts on [Test helpers dashboard](#test-helpers-dashboard)&thinsp;📊.
    Look at different timespans:

    a.  The uptime of the test helpers should be staggered by a week
        depending on [Test helper rotation](#test-helper-rotation)&thinsp;⚙.

    b.  The in-flight requests and requests per second should be
        consistent across hosts, except for `0.th.ooni.org`. See
        [Test helpers list](#test-helpers-list)&thinsp;🐝 for details.

    c.  Review CPU load, memory usage and run duration percentiles.

3.  Review [Test helper failure rate notebook](#test-helper-failure-rate-notebook)&thinsp;📔

4.  For more detailed investigation there is also a [test helper notebook](https://jupyter.ooni.org/notebooks/notebooks/2023%20%5Bfederico%5D%20test%20helper%20metadata%20in%20fastpath.ipynb)

5.  Log on the hosts using
    `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -Snone root@0.th.ooni.org`

6.  Run `journalctl --since '1 hour ago'` or review logs using the query
    below.

7.  Run `top`, `strace`, `tcpdump` as needed.

8.  The rotation tool can be started at any time to rotate away failing
    test helpers. The rotation script will always pick the oldest host
    for rotation. ⚠️ Due to the propagation time of changes in the DNS
    rotating many test helpers too quickly can impact the probes.

    a.  Log on [backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥

    b.  Check the last run using
        `sudo systemctl status ooni-rotation.timer`

    c.  Review the logs using `sudo journalctl -u ooni-rotation`

    d.  Run `sudo systemctl restart ooni-rotation` and monitor the logs.

9.  Review the charts on [Test helpers dashboard](#test-helpers-dashboard)&thinsp;📊
    during and after the rotation.

10. Summarize traffic hitting a test helper using the following commands:

    Top 10 miniooni probe IP addresses (Warning: this is sensitive data)

    `tail -n 100000 /var/log/nginx/access.log | grep miniooni | cut -d' ' -f1|sort|uniq -c|sort -nr|head`

    Similar, with anonimized IP addresses:

    `grep POST /var/log/nginx/access.log | grep miniooni | cut -d'.' -f1-3 | head -n 10000 |sort|uniq -c|sort -nr|head`

    Number of requests from miniooni probe in 10-minutes buckets:

    `grep POST /var/log/nginx/access.log | grep miniooni | cut -d' ' -f4 | cut -c1-17 | uniq -c`

    Number of requests from miniooni probe in 1-minute buckets:

    `grep POST /var/log/nginx/access.log | grep miniooni | cut -d' ' -f4 | cut -c1-18 | uniq -c`

    Number of requests grouped by hour, cache HIT/MISS/etc, software name and version

    `head -n 100000 /var/log/nginx/access.log | awk '{print $4, $6, $13}' | cut -c1-15,22- | sort | uniq -c | sort -n`

To extract data from the centralized log database
on [monitoring.ooni.org](#monitoring.ooni.org)&thinsp;🖥 you can use:

``` sql
SELECT message FROM logs
WHERE SYSLOG_IDENTIFIER = 'oohelperd'
ORDER BY __REALTIME_TIMESTAMP DESC
LIMIT 10
```

> **note**
> The table is indexed by `__REALTIME_TIMESTAMP`. Limiting the range by time can significantly increase query performance.


See [Selecting test helper for rotation](#selecting-test-helper-for-rotation)&thinsp;🐞

## Legacy credentials store

A private repository <https://github.com/ooni/private> contains team
credentials, including username/password tuples, GPG keys and more.

> **warning**
> The credential file is GPG-encrypted as `credentials.json.gpg`. Do not
> commit the cleartext `credentials.json` file.

> **note**
> The credentials are stored in a JSON file to allow a flexible,
> hierarchical layout. This allow storing metadata like descriptions on
> account usage, dates of account creations, expiry, and credential
> rotation time.

The tool checks JSON syntax and sorts keys automatically.


#### Listing file contents

    git pull
    make show

#### Editing contents

    git pull
    make edit
    git commit credentials.json.gpg -m "<message>"
    git push

#### Extracting a credential programmatically:

    git pull
    ./extract 'grafana.username'

> **note**
> this can be used to automate credential retrieval from other tools, e.g.
> [Ansible](#ansible)&thinsp;🔧

#### Updating users allowed to decrypt the credentials file

Edit `makefile` to add or remove recipients (see `--recipient`)

Then run:

    git pull
    make decrypt encrypt
    git commit makefile credentials.json.gpg
    git push
