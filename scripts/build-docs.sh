#!/bin/bash
DOCS_ROOT=dist/docs/
REPO_NAME="ooni/devops"
MAIN_BRANCH="main"
COMMIT_HASH=$(git rev-parse --short HEAD)

mkdir -p $DOCS_ROOT

strip_title() {
    # Since the title is already present in the frontmatter, we need to remove
    # it to avoid duplicate titles
    local infile="$1"
    cat $infile | awk 'BEGIN{p=1} /^#/{if(p){p=0; next}} {print}'
}

generate_doc() {
    local slug="$1"
    local order="$2"
    local input_file="$3"
    local output_file="$4"
    local title="$5"
    local description="$6"

    cat <<EOF>"$DOCS_ROOT/$output_file"
---
# Do not edit! This file is automatically generated
# version: $REPO_NAME/$input_file:$COMMIT_HASH
title: $title
description: $description
slug: $slug
sidebar:
    order: $order
---
EOF
    echo "[edit file](https://github.com/$REPO_NAME/edit/$MAIN_BRANCH/$input_file)" >> "$DOCS_ROOT/$output_file"
    strip_title "$input_file" >> "$DOCS_ROOT/$output_file"
}

generate_doc 0 "README.md" "00-index.md" "OONI Devops" "OONI OONI Devops" "devops"
generate_doc 1  "docs/Infrastructure.md" "01-infrastructure.md" "Infrastructure" "Infrastructure documentation" "devops/infrastructure"
generate_doc 2 "docs/MonitoringAlerts.md" "02-monitoring-alerts.md" "Monitoring" "Monitoring and Alerts documentation" "devops/monitoring"
generate_doc 3 "docs/Runbooks.md" "03-runbooks.md" "Runbooks" "Runbooks docs" "devops/runbooks"
generate_doc 4 "docs/IncidentResponse.md" "04-incident-response.md" "Incident response" "Incident response handling guidelines" "devops/incident-response"
generate_doc 5 "tf/README.md" "05-terraform.md" "Terraform setup" "Terraform setup" "devops/terraform"
generate_doc 6 "ansible/README.md" "06-ansible.md" "Ansible setup" "Ansible setup" "devops/ansible"
generate_doc 7 "docs/Tools.md" "07-tools.md" "Misc Tools" "Misc Tools" "devops/tools"
generate_doc 8 "docs/DebianPackages.md" "08-debian-packages.md" "Debian Packages" "Debian Packages" "devops/debian-packages"
generate_doc 9 "docs/LegacyDocs.md" "09-legacy-docs.md" "Legacy Documentation" "Legacy Documentation" "devops/legacy-docs"
