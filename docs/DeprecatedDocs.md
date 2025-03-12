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
