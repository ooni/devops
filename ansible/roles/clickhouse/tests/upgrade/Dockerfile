# A Debian 12 host with systemd, like the ClickHouse servers, for the role to install on
FROM docker.io/library/debian:12
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends systemd systemd-sysv python3 ca-certificates sudo >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/apt.conf.d/docker-clean  # keep downloaded packages in the shared cache
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
