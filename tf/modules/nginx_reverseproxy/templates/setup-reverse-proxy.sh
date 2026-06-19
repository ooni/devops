#!/bin/bash
set -e

sudo apt update
sudo apt install -y nginx

tmpfile=$(mktemp /tmp/nginx-config.XXXXXX)
cat > $tmpfile <<EOF
server {
    listen 80;

    server_name _;

    location / {
        proxy_pass ${proxy_pass_url};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;

        ${extra_path_config}
    }
}
EOF
sudo mv $tmpfile /etc/nginx/sites-available/default

tmpfile=$(mktemp /tmp/nginx-config.XXXXXX)
cat > $tmpfile <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
  worker_connections 768;
}

http {
  sendfile on;
  tcp_nopush on;
  types_hash_max_size 2048;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  map \$remote_addr \$remote_addr_anon {
    ~(?P<ip>\\d+\\.\\d+\.\\d+)\.    \$ip.0;
    ~(?P<ip>[^:]+:[^:]+):       \$ip::;
    default                     0.0.0.0;
  }

  # log anonymized ipaddr and caching status
  log_format ooni_nginx_fmt '\$remote_addr_anon \$upstream_cache_status [\$time_local] '
      '"\$request" \$status \$body_bytes_sent "\$http_referer" "\$http_user_agent"';

  ${extra_nginx_config}

  access_log syslog:server=unix:/dev/log ooni_nginx_fmt;
  error_log syslog:server=unix:/dev/log;

  gzip on;

  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}
EOF
sudo mv $tmpfile /etc/nginx/nginx.conf

sudo mkdir -p /var/cache/nginx
sudo chown -R www-data /var/cache/nginx

sudo nginx -t
sudo systemctl reload nginx
