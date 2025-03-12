# Infrastructure

Our infrastructure is primarily spread across the following providers:

* Hetzner, for dedicated hosts
* DigitalOcean, for VPSs which require IPv6 support
* AWS, for most cloud based infrastrucutre hosting

We manage the deployment and configuration of hosts through a combination of ansible and terraform.

## Infrastructure Tiers

We divide our infrastructure components into 3 tiers:

- **Tier 0: Critical**: These are mission critical infrastructure components. If these become unavailable or have significant disruption, it will have a major impact.

- **Tier 1: Essential**: These components are important, but not as critical as
  tier 0. They are part of our core operations, but if they become unavailable
  the impact is important, but not major.

- **Tier 2: Non-Essential**: These are auxiliary components. Their
  unavailability does not have a major impact.

### Tier 0 (Critical) components

- [ ] Probe Services (collector specifically)
- [ ] Fastpath (part responsible for storing post-cans)
- [x] DNS configuration
- [ ] OONI bridges
- [x] Web Connectivity test helpers

### Tier 1 (Essential) components

- [ ] OONI API measurement listing
- [x] OONI Explorer
- [x] OONI Run
- [ ] Monitoring
- [ ] OONI.org website
- [x] Code signing
- [ ] OONI Data analysis pipeline
- [x] OONI Findings API
- [x] Website analytics

### Tier 2 (Non-Essential) components

- [ ] Test list editor
- [ ] Jupyter notebooks
- [ ] Countly

## Hosts

This section provides a summary of the backend hosts described in the
rest of the document.

A full list is available at
<https://github.com/ooni/devops/blob/master/ansible/inventory> -
also see [Ansible](#ansible)&thinsp;🔧

### backend-fsn.ooni.org

Public-facing production backend host, receiving the deployment of the
packages:

- [ooni-api](legacybackend/operations/#ooni-api-package)&thinsp;📦

- [fastpath](legacybackend/operations/#fastpath-package)&thinsp;📦

- [analysis](legacybackend/operations/#analysis-package)&thinsp;📦

- [detector](legacybackend/operations/#detector-package)&thinsp;📦

### backend-hel.ooni.org

Standby / pre-production backend host. Runs the same software stack as
[backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥, plus the
[OONI bridges](#ooni-bridges)&thinsp;⚙

### monitoring.ooni.org

Runs the internal monitoring stack, including
[Jupyter Notebook](#tool:jupyter), [Prometheus](#prometheus)&thinsp;🔧,
[Vector](#vector)&thinsp;🔧 and
[ClickHouse instance for logs](#clickhouse-instance-for-logs)&thinsp;⚙

## Etckeeper

Etckeeper <https://etckeeper.branchable.com/> is deployed on backend
hosts and keeps the `/etc` directory under git version control. It
commits automatically on package deployment and on timed runs. It also
allows doing commits manually.

To check for history of the /etc directory:

```bash
sudo -i
cd /etc
git log --raw
```

And `git diff` for unmerged changes.

Use `etckeeper commit <message>` to commit changes.

:::tip
Etckeeper commits changes automatically when APT is used or on daily basis, whichever comes first.
:::

## Devops credentials

Credentials necessary for the deployment of backend infrastructure components should be stored inside of [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html). The same key name should be used in both production and development environment, but a different value shall be used across environments.

:::note
We previously were using secrets manager, but are in the process of moving over all secerets to parameter store, see: https://github.com/ooni/devops/issues/114.

Once this is complete this note can be removed.
:::

## DNS and Domains

The primary domains used by the backend are:
- `ooni.org`
- `ooni.io`
- `ooni.nu`

DNS is managed inside of route53. Where a static configuration is needed, this is added to the terraform `tf/environments/prod/dns_records.tf` file. For records that are being populated as part of IaC deployments, those can be registerred and written directly using terraform itself.

For the `ooni.io` and `ooni.nu` zones, we also have delegated two sub zones each one for the `dev` and one for the `prod` environment. This allows the dev environment to manage it's own zone, like the production environment would, but also properly compatmentalize it.

This leads us to having the following zones:
* `ooni.org` root zone, managed in the prod environment
* `ooni.io` root zone, managed in the prod environment
* `ooni.nu` root zone, managed in the prod environment
* `prod.ooni.io` delegated zone, managed in the prod environment
* `prod.ooni.nu` delegated zone, managed in the prod environment
* `dev.ooni.io` delegated zone, managed in the dev environment
* `dev.ooni.nu` delegated zone, managed in the dev environment

### DNS naming policy

The public facing name of services, follows this format:

- `<service>.ooni.org`

Examples:

- `explorer.ooni.org`
- `run.ooni.org`

Public-facing means the FQDNs are used directly by external users, services, or
embedded in the probes. They cannot be changed or retired without causing
outages.

Use public facing names sparingly and when possible start off by creating a
private name first.
Not every host needs to have a public facing name. For example staging and
testing environments might not have a public facing name.

Each service also has public name which points to the specific host running that
service, and these are hosted in the `.io` zone.
This is helpful because sometimes you might have the same host running multiple
services or you might also have multiple services behind the same public service
endpoint (eg. in the case of an API gateway setup).

Name in the `.io` zone should always include also the environment name they are
related to:

- `<service>.prod.ooni.io` for production services
- `<service>.test.ooni.io` for test services

When there may be multiple instances of a service running, you can append a
number to the service name. Otherwise the service name should be only alphabetic
characters.

Examples:

- `clickhouse.prod.ooni.io`
- `postgres0.prod.ooni.io`
- `postgres1.prod.ooni.io`
- `prometheus.prod.ooni.io`
- `grafana.prod.ooni.io`

Finally, the actual host which runs the service, should have a FQDN defined
inside of the `.nu` zone.

This might not apply to every host, especially in a cloud environment. The FQDN
in the `.nu` are the ones which are going to be stored in the ansible inventory
file and will be used as targets for configuration management.

The structure of these domains is:

- `<name>.<location>.[prod|test].ooni.nu`

The location tag can be either just the provider name or provider name `-` the location.

Here is a list of location tags:

- `htz-fsn`: Hetzner on Falkenstein
- `htz-hel`: Hetzner in Helsinki
- `grh-ams`: Greenhost in Amsterdam
- `grh-mia`: Greenhost in Miami
- `aws-fra`: AWS in Europe (Frankfurt)

Examples:

- `monitoring.htz-fsn.prod.ooni.nu`
