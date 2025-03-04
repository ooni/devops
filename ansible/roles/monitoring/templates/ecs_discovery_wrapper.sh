#! /bin/bash

# This script is a wrapper over the ECS discovery script with the environment variables properly set

# We read the environment variables from /etc/ooni/ecs_discovery_settings.sh

set -e

# Check if the --env argument is provided
if [[ "$#" -lt 2 || "$1" != "--env" ]]; then
    echo "Usage: $0 --env <dev|prod>"
    exit 1
fi

# Extract the environment value
ENV="$2"

# Validate the argument
if [[ "$ENV" != "dev" && "$ENV" != "prod" ]]; then
    echo "Error: --env must be either 'dev' or 'prod'"
    exit 1
fi


# Load env variables from this file
source /etc/ooni/ecs_discovery_settings.sh

# Execute different commands based on the environment
if [[ "$ENV" == "dev" ]]; then    
    ecs-discovery.py --output-file {{ecs_targets_dir}}/dev.json --env dev --secret-key $AWS_SECRET_KEY_DEV --access-key $AWS_ACCESS_KEY_ID_DEV
elif [[ "$ENV" == "prod" ]]; then
    ecs-discovery.py --output-file {{ecs_targets_dir}}/prod.json --env prod --secret-key $AWS_SECRET_KEY_PROD --access-key $AWS_ACCESS_KEY_ID_PROD
fi
