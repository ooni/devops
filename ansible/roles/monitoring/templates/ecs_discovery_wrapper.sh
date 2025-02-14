#! /bin/bash

# This script is a wrapper over the ECS discovery script with the environment variables properly set

# We read the environment variables from /etc/ooni/ecs_discovery_settings.sh

source /etc/ooni/ecs_discovery_settings.sh
ecs-discovery.py --output-file {{ecs_targets_file}}