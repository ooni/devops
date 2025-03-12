# Incident response

## On-call preparation
Review [Alerting](#alerting)&thinsp;💡 and check
[Grafana dashboards](#grafana-dashboards)&thinsp;💡

On Android devices the following apps can be used:

 * [Slack](#slack)&thinsp;🔧 app with audible notifications from the
    #ooni-bots channel

 * [Grafana](#grafana)&thinsp;🔧 viewer
    <https://play.google.com/store/apps/details?id=it.ksol.grafanaview>

## Severities

When designing architecture of backend components or handling incidents it can be useful to have
defined severities and tiers.

A set of guidelines are described at <https://google.github.io/building-secure-and-reliable-systems/raw/ch16.html#establish_severity_and_priority_models>
This section presets a simplified approach to prioritizing incident response.

In this case there is no distinction between severity and priority. Impact and response time are connected.

Incidents and alarms from monitoring can be classified by severity levels based on their impact:

 - 1: Serious security breach or data loss; serious loss of privacy impacting users or team members; legal risks.
 - 2: Downtime impacting service usability for a significant fraction of users or a tier 0 component; Serious security vulnerability.
      Examples: probes being unable to submit measurements
 - 3: Downtime or poor performance impacting secondary services (tier 1 or above); anything that can cause a level 2 event if not addressed within 24h; outages of monitoring infrastructure
 - 4: Every other event that requires attention within 7 days

For an outline of infrastructure tiers see [infrastructure tiers](devops/infrastructure).

### Relations and dependencies between services

Tiers are useful during design and deployment as a way to minimize risk of outages and avoid unexpected cascading failures.

Having a low tier value should not be treated as a sign of "importance" for a component, but a liability.

Pre-production deployment stages (e.g. testbed) have tier level >= 5

In this context a component can be a service as a whole, or a running process (daemon), a host, a hardware device, etc.
A component can contain other components.

A component "A" is said to "hard depend" on another component "B" if an outage of B triggers an outage of A.

It can also "soft depend" on another component if an outage of the latter triggers only a failure of a subsystem, or an ancillary feature or a reasonably short downtime.

Regardless of tiers, components at a higher stage, (e.g. production) cannot depend and/or receive data from lower stages. The opposite is acceptable.

Components can only hard-depend on other components at the same tier or with lower values.
E.g. a Tier 2 component can depend on a Tier 1 but not the other way around.
If it happens, the Tier 2 component should be immediatly re-classified as Tier 1 and treated accordingly (see below).

E.g. anything that handles real-time failover for a service should be treated at the same tier (or lower value) as the service.

Redundant components follow a special rule. For example, the "test helper" service provided to the probes, as a whole, should be considered tier 2 at least,
as it can impact all probes preventing them from running tests succesfully.
Yet, test helper processes and VMs can be considered tier 3 or even 4 if they sit behind a load balancer that can move traffic away from a failing host reliably
and with no significant downtime.

Example: An active/standby database pair provides a tier 2 service. An automatic failover tool is triggered by a simple monitoring script.
Both have to be labeled tier 2.

### Handling incidents

Depending on the severity of an event a different workflow can be followed.

An example of incident management workflow can be:

| Severity | Response time | Requires conference call | Requires call leader | Requires postmortem | Sterile |
| -------- | ------- | ------ | -------- | ------- | ------ |
| 1 | 2h | Yes | Yes | Yes | Yes |
| 2 | 8h | Yes | No | Yes | Yes |
| 3 | 24h | No | No | No | Yes |
| 4 | 7d | No | No | No | No |

The term "sterile" is named after <https://en.wikipedia.org/wiki/Sterile_flight_deck_rule> - during the investigation the only priority should be to solve the issue at hand.
Other investigations, discussions, meetings should be postponed.

When in doubt around the severity of an event, always err on the safe side.

### Regular operations

Based on the tier of a component, development and operation can follow different rules.

An example of incident management workflow can be:

| Tier | Require architecture review | Require code review | Require 3rd party security review | Require Change Management |
| -------- | ------- | ------ | -------- | ------- |
| 1 | Yes | Yes | Yes | Yes |
| 2 | Yes | Yes | No | No |
| 3 | No | Yes | No | No |
| 4 | No | No | No | No |

"Change Management" refers to planning operational changes in advance and having team members review the change to be deployed in advance.

E.g. scheduling a meeting to perform a probe release, have 2 people reviewing the metrics before and after the change.


## Redundant notifications
If needed, a secondary channel for alert notification can be set up
using <https://ntfy.sh/>

Ntfy can host a push notification topic for free.

For example <https://ntfy.sh/ooni-7aGhaS> is currently being used to
notify the outcome of CI runs from
<https://github.com/ooni/backend/blob/0ec9fba0eb9c4c440dcb7456f2aab529561104ae/.github/workflows/test_new_api.yml>

An Android app is available:
<https://f-droid.org/en/packages/io.heckel.ntfy/>

[Grafana](#grafana)&thinsp;🔧 can be configured to send alerts to ntfy.sh
using a webhook.

### Measurement drop tutorial

This tutorial provides examples on how to investigate a drop in measurements.
It is based on an incident where a drop in measurement was detected and the cause was not immediately clear.

It is not meant to be a step-by-step runbook but rather give hints on what data to look for, how to generate charts and identify the root cause of an incident.

A dedicated issue can be used to track the incident and the investigation effort and provide visibility:
https://github.com/ooni/sysadmin/blob/master/.github/ISSUE_TEMPLATE/incident.md
The issue can be filed during or after the incident depending on urgency.

Some of the examples below come from
https://jupyter.ooni.org/notebooks/notebooks/android_probe_release_msm_drop_investigation.ipynb
During an investigation it can be good to create a dedicated Jupyter notebook.

We started with reviewing:

 * <https://jupyter.ooni.org/view/notebooks/jupycron/autorun_android_probe_release.html>
   No issues detected as the charts show a short timespan.
 * The charts on [Test helpers dashboard](#test-helpers-dashboard)&thinsp;📊.
   No issues detected here.
 * The [API and fastpath](#api-and-fastpath)&thinsp;📊 dashboard.
   No issues detected here.
 * The [Long term measurements prediction notebook](#long-term-measurements-prediction-notebook)&thinsp;📔
   The decrease was clearly showing.

Everything looked OK in terms of backend health. We then generated the following charts.

The chunks of Python code below are meant to be run in
[Jupyter Notebook](#jupyter-notebook)&thinsp;🔧 and are mostly "self-contained".
To be used you only need to import the
[Ooniutils microlibrary](#ooniutils-microlibrary)&thinsp;💡:

``` python
%run ooniutils.ipynb
```

The "t" label is commonly used on existing notebooks to refer to hour/day/week time slices.

We want to plot how many measurements we are receiving from Ooniprobe Android in unattended runs, grouped by day and by `software_version`.

The last line generates an area chart using Altair. Notice that the `x` and `y` and `color` parameters match the 3 columns extracted by the `SELECT`.

The `GROUP BY` is performed on 2 of those 3 columns, while `COUNT(*)` is counting how many measurements exist in each t/software_version "bucket".

The output of the SQL query is just a dataframe with 3 columns. There is no need to pivot or reindex it as Altair does the data transformation required.

> **note**
> Altair refuses to process dataframes with more than 5000 rows.

``` python
x = click_query("""
    SELECT
      toStartOfDay(toStartOfWeek(measurement_start_time)) AS t,
      software_version,
      COUNT(*) AS msm_cnt
    FROM fastpath
    WHERE measurement_start_time > today() - interval 3 month
    AND measurement_start_time < today()
    AND software_name = 'ooniprobe-android-unattended'
    GROUP BY t, software_version
""")
alt.Chart(x).mark_area().encode(x='t', y='msm_cnt', color='software_version').properties(width=1000, height=200, title="Android unattended msm cnt")
```

The generated chart was:

![chart](../../../assets/images-backend/msm_drop_investigation_1.png)

From the chart we concluded that the overall number of measurements have been decreasing since the release of a new version.
We also re-ran the plot by filtering on other `software_name` values and saw no other type of probe was affected.

> **note**
> Due to a limitation in Altair, when grouping time by week use
> `toStartOfDay(toStartOfWeek(measurement_start_time)) AS t`

Then we wanted to measure how many measurements are being collected during each `web_connectivity` test run.
This is to understand if probes are testing less measurements in each run.

The following Python snippet uses nested SQL queries. The inner query groups measurements by time, `software_version` and `report_id`,
and counts how many measurements are related to each `report_id`.
The outer query "ignores" the `report_id` value and `quantile()` is used to extract the 50 percentile of `msm_cnt`.

> **note**
> The use of double `%%` in `LIKE` is required to escape the `%` wildcard. The wildcard is used to match any amount of characters.

``` python
x = click_query("""
    SELECT
        t,
        quantile(0.5)(msm_cnt) AS msm_cnt_p50,
        software_version
    FROM (
        SELECT
            toStartOfDay(toStartOfWeek(measurement_start_time)) AS t,
            software_version,
            report_id,
            COUNT(*) AS msm_cnt
        FROM fastpath
        WHERE measurement_start_time > today() - interval 3 month
        AND test_name = 'web_connectivity'
        AND measurement_start_time < today()
        AND software_name = 'ooniprobe-android-unattended'
        AND software_version LIKE '3.8%%'
        GROUP BY t, software_version, report_id
    ) GROUP BY t, software_version
""")
alt.Chart(x).mark_line().encode(x='t', y='msm_cnt_p50', color='software_version').properties(width=1000, height=200, title="Android unattended msmt count per report")
```

We also compared different version groups and different `software_name`.
The output shows that indeed the number of measurements for each run is significantly lower for the newly released versions.

![chart](../../../assets/images-backend/msm_drop_investigation_4.png)

To update the previous Python snippet to group measurements by a different field, change `software_version` into the new column name.
For example use `probe_cc` to show a chart with a breakdown by probe country name. You should change `software_version` once in each SELECT part,
then in the last two `GROUP BY`, and finally in the `color` line at the bottom.

We did such change to confirm that all countries were impacted in the same way. (The output is not included here as not remarkable)

Also, `mark_line` on the bottom line is used to create line charts. Switch it to `mark_area` to generate *stacked* area charts.
See the previous two charts as examples.

We implemented a change to the API to improve logging the list of tests returned at check-in: <https://github.com/ooni/backend/pull/781>
and reviewed monitored the logs using `sudo journalctl -f -u ooni-api`.

The output showed that the API is very often returning 100 URLs to probes.

We then ran a similar query to extract the test duration time by calculating
`MAX(measurement_start_time) - MIN(measurement_start_time) AS delta` for each `report_id` value:

``` python
x = click_query("""
    SELECT t, quantile(0.5)(delta) AS deltaq, software_version
    FROM (
        SELECT
            toStartOfDay(toStartOfWeek(measurement_start_time)) AS t,
            software_version,
            report_id,
            MAX(measurement_start_time) - MIN(measurement_start_time) AS delta
        FROM fastpath
        WHERE measurement_start_time > today() - interval 3 month
        AND test_name = 'web_connectivity'
        AND measurement_start_time < today()
        AND software_name = 'ooniprobe-android-unattended'
        AND software_version LIKE '3.8%%'
        GROUP BY t, software_version, report_id
    ) GROUP BY t, software_version
""")
alt.Chart(x).mark_line().encode(x='t', y='deltaq', color='software_version').properties(width=1000, height=200, title="Android unattended test run time")
```

![chart](../../../assets/images-backend/msm_drop_investigation_2.png)

The chart showed that the tests are indeed running for a shorter amount of time.

> **note**
> Percentiles can be more meaningful then averages.
> To calculate quantiles in ClickHouse use `quantile(<fraction>)(<column_name>)`.

Example:

``` sql
quantile(0.1)(delta) AS deltaq10
```

Wondering if the slowdown was due to slower measurement execution or other issues, we also generated a table as follows.

> **note**
> Showing color bars allows to visually inspect tables more quickly. Setting the axis value to `0`, `1` or `None` helps readability:
> `y.style.bar(axis=None)`

Notice the `delta / msmcnt AS seconds_per_msm` calculation:

``` python
y = click_query("""
    SELECT
        quantile(0.1)(delta) AS deltaq10,
        quantile(0.3)(delta) AS deltaq30,
        quantile(0.5)(delta) AS deltaq50,
        quantile(0.7)(delta) AS deltaq70,
        quantile(0.9)(delta) AS deltaq90,

        quantile(0.5)(seconds_per_msm) AS seconds_per_msm_q50,
        quantile(0.5)(msmcnt) AS msmcnt_q50,

    software_version, software_name
    FROM (
        SELECT
            software_version, software_name,
            report_id,
            MAX(measurement_start_time) - MIN(measurement_start_time) AS delta,
            count(*) AS msmcnt,
            delta / msmcnt AS seconds_per_msm
        FROM fastpath
        WHERE measurement_start_time > today() - interval 3 month
        AND test_name = 'web_connectivity'
        AND measurement_start_time < today()
        AND software_name IN ['ooniprobe-android-unattended', 'ooniprobe-android']
        AND software_version LIKE '3.8%%'
        GROUP BY software_version, report_id, software_name
    ) GROUP BY software_version, software_name
    ORDER by software_version, software_name ASC
""")
y.style.bar(axis=None)
```

![chart](../../../assets/images-backend/msm_drop_investigation_3.png)

In the table we looked at the `seconds_per_msm_q50` column: the median time for running each test did not change significantly.

To summarize:
 * The backend appears to deliver the same amount of URLs to the Probes as usual.
 * The time required to run each test is rougly the same.
 * Both the number of measurements per run and the run time decreased in the new releases.

## Github issues

### Selecting test helper for rotation
See <https://github.com/ooni/backend/issues/721>


### Document Tor targets
See <https://github.com/ooni/backend/issues/761>


### Disable unnecessary ClickHouse system tables
See <https://github.com/ooni/backend/issues/779>


### Feed fastpath from JSONL
See <https://github.com/ooni/backend/issues/778>


### Implement Grafana dashboard and alarms backup
See <https://github.com/ooni/backend/issues/770>
