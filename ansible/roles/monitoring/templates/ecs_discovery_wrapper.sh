#! /bin/bash

# This script is a wrapper over the ECS discovery script with the environment variables properly set

# We read the environment variables from /etc/ooni/ecs_discovery_settings.sh


# Load env variables from this file
source /etc/ooni/ecs_discovery_settings.sh

ecs-discovery.py --output-file {{ecs_targets_dir}}/dev.json --env dev --secret-key $AWS_SECRET_KEY_DEV --access-key $AWS_ACCESS_KEY_ID_DEV
# ecs-discovery.py --output-file {{ecs_targets_dir}}/prod.json --env prod --secret-key $AWS_SECRET_KEY_PROD --access-key $AWS_ACCESS_KEY_ID_PROD
