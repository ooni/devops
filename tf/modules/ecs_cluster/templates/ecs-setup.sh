#!/bin/bash

cat <<'EOF' >> /etc/ecs/ecs.config
ECS_CLUSTER=${ecs_cluster_name}
ECS_LOGLEVEL=debug
ECS_CONTAINER_INSTANCE_TAGS=${jsonencode(ecs_cluster_tags)}
ECS_ENABLE_TASK_IAM_ROLE=true
EOF

# Exit on error and show running commands
set -ex

# Install node exporter on this machine
# IN CASE OF UPDATE: You can find this downloads and its checksums here: 
# https://prometheus.io/download/#node_exporter
DOWNLOAD_LINK='https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz'
CHECKSUM='6809dd0b3ec45fd6e992c19071d6b5253aed3ead7bf0686885a51d85c6643c66'

# Download node exporter binary
echo "Downloading node exporter..."
cd /tmp
curl -O -L $DOWNLOAD_LINK

# Checksum the file
ACTUAL_FILE=$(ls | grep node_exporter-*.*-amd64.tar.gz)
echo "$CHECKSUM $ACTUAL_FILE" | sha256sum -c -
if [[ $? -eq 0 ]]; then
    echo "Node exporter checksum validation OK!"
else
    echo "[ERROR] Checksum validation for node exporter failed!" >&2
    exit 1
fi

# Move it to an executable path
tar xvfz node_exporter-*.*-amd64.tar.gz
chmod 555 node_exporter-*.*-amd64/node_exporter
sudo mv node_exporter-*.*-amd64/node_exporter /usr/local/bin/


# Add node exporter service user
echo "Creating node exporter user..."
sudo useradd -rs /bin/false node_exporter

# Create service file for node exporter
echo "Setting up service file..."
cat <<'EOF' >> /tmp/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target
[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter
[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/node_exporter.service /etc/systemd/system

# update systemd
echo "Updating systemd..."
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter