#! /bin/bash

# This is a configuration file for the ECS discovery cronjob that discovers ECS tasks
# to be monitored by Prometheus

export AWS_REGION={{ecs_aws_region}}
export AWS_SECRET_KEY_DEV={{monitoring_secret_key_dev}}
export AWS_ACCESS_KEY_ID_DEV={{monitoring_access_key_dev}}

export AWS_SECRET_KEY_PROD={{monitoring_secret_key_dev}}
export AWS_ACCESS_KEY_ID_PROD={{monitoring_access_key_dev}}