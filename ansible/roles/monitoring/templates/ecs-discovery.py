#!/usr/bin/python3
import argparse
import dataclasses
from typing import List, Dict, Any
import logging
import os
from pathlib import Path
from datetime import datetime, timezone
import json

import boto3

parser = argparse.ArgumentParser(
    description="""
    ECS Discovery: Find ECS-deployed services by pulling the
    data from AWS using the boto3 library.
                                 
    This command line tool will list all currently running 
    ECS services with their host and port.   
                                 
    You can list them into stdout or write them in a file
    compatible with prometheus file-based discovery
"""
)

parser.add_argument(
    "--show", action="store_true", help="Display discovered services in STDOUT"
)
parser.add_argument(
    "--region",
    type=str,
    help="AWS region. If not provided, will be pulled from environment: AWS_REGION",
    default=None,
)
parser.add_argument(
    "--secret-key",
    type=str,
    help="Secret Access key. If not provided, will be pulled from environment: AWS_SECRET_KEY",
    default=None,
)
parser.add_argument(
    "--access-key",
    type=str,
    help="Access key ID. If not provided, will be pulled from environment: AWS_ACCESS_KEY_ID",
    default=None,
)
parser.add_argument(
    "--output-file",
    type=str,
    help="Where to write json file with targets. If not provided it won't write to disk",
    default="targets.json",
)


@dataclasses.dataclass
class ECSService:
    private_ip: str
    port: int
    container_name: str
    task_arn: str
    ec2_instance_id: str
    cluster: str
    date_discovered : datetime


class ECSDiscovery:

    def __init__(self, region: str, secret_key: str, access_key: str) -> None:
        self.region = region
        self.secret_key = secret_key
        self.access_key = access_key
        self.ecs_client = boto3.client(
            "ecs",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
        )

    def list_services(self) -> List[ECSService]:
        """
        List all ECS services in every cluster
        """

        logging.info("Retrieving clusters...")
        clusters = self._list_clusters()
        results: List[ECSService] = []

        for cluster_desc in clusters:
            cluster_name = cluster_desc["clusterName"]

            logging.info(f"Retrieving tasks for cluster {cluster_name}...")
            tasks = self._list_tasks(cluster_desc)

            logging.info(
                f"Retrieving container instance information for found tasks..."
            )
            # map from container instance ARN to Instance description
            container_instance_descriptions = (
                self._list_container_instance_descriptions(tasks, cluster_name)
            )

            for task_description in tasks:
                task_arn = task_description["taskArn"]

                #  Describe container instance
                container_instance_arn = task_description["containerInstanceArn"]
                container_instance_description = container_instance_descriptions[
                    container_instance_arn
                ]
                instance_id = container_instance_description["ec2InstanceId"]

                for container in task_description["containers"]:

                    container_name = container["name"]
                    for binding in container["networkBindings"]:
                        # Get the task port
                        logging.info(
                            f"Found port: {binding['hostPort']} for container {container_name} in instance {instance_id}",
                        )

                        # Still doesn't know the private IP for the EC2 instance
                        results.append(
                            ECSService(
                                "",
                                port=binding["hostPort"],
                                container_name=container_name,
                                task_arn=task_arn,
                                ec2_instance_id=instance_id,
                                cluster=cluster_name,
                                date_discovered=datetime.now(timezone.utc)
                            )
                        )

        self._set_ec2_private_ips(results)

        return results

    def _list_clusters(self) -> List[Dict[str, Any]]:
        """
        List all clusters, including descriptions
        """
        clusters = self.ecs_client.list_clusters()
        clusters_arns = clusters["clusterArns"]
        clustersDescriptions = self.ecs_client.describe_clusters(
            clusters=clusters_arns
        )["clusters"]

        return clustersDescriptions

    def _list_tasks(self, cluster: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        List all tasks within a cluster, including descriptions
        """
        cluster_name = cluster["clusterName"]
        cluster_arn = cluster["clusterArn"]
        tasks = self.ecs_client.list_tasks(cluster=cluster_arn)
        task_arns = tasks["taskArns"]
        task_descriptions = self.ecs_client.describe_tasks(
            cluster=cluster_name, tasks=task_arns
        )["tasks"]
        return task_descriptions

    def _list_container_instance_descriptions(
        self, tasks: List[Dict[str, Any]], cluster_name: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        List all container instances, including descriptions. 

        The resulting dict has the shape: Container ARN -> Container Description
        """

        container_instances_ids = []
        for task_description in tasks:
            container_instance_arn = task_description["containerInstanceArn"]
            container_instance_id = container_instance_arn.split("/")[-1]
            container_instances_ids.append(container_instance_id)

        # This will map from container instance arn to its description
        container_arn_to_description = {}
        container_instances_descriptions = self.ecs_client.describe_container_instances(
            cluster=cluster_name, containerInstances=container_instances_ids
        )
        for container_inst_desc in container_instances_descriptions[
            "containerInstances"
        ]:
            container_arn_to_description[
                container_inst_desc["containerInstanceArn"]
            ] = container_inst_desc

        return container_arn_to_description

    def _set_ec2_private_ips(self, services: List[ECSService]):
        """
        Set up the private IP for the given list of services
        """

        ec2_client = boto3.client(
            "ec2",
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
        )
        instance_ids = [service.ec2_instance_id for service in services]
        instance_description = ec2_client.describe_instances(InstanceIds=instance_ids)

        instances = {}
        for reservation in instance_description["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]
                instances[instance_id] = instance

        for service in services:
            private_ip = instances[service.ec2_instance_id]["PrivateIpAddress"]
            service.private_ip = private_ip

def to_prom_json(services : List[ECSService]) -> List[Dict[str, Any]]:
    """
    Convert a list of service objects into a prometheus-compatible list of dict
    """
    services_json = []

    for service in services:
        services_json.append({
            "targets" : [
                f"{service.private_ip}:{service.port}"
            ],
            "labels": {
                "job" : service.container_name,
                "instance" : service.ec2_instance_id,
                "task" : service.task_arn,
                "date_discovered" : service.date_discovered.isoformat()
            }
        })

    return services_json


def main(args : argparse.Namespace):

    logging.basicConfig(level=logging.INFO)

    # Collect arguments
    secret_key = args.secret_key or os.environ.get("AWS_SECRET_KEY")
    access_key = args.access_key or os.environ.get("AWS_ACCESS_KEY_ID")
    region = args.region or os.environ.get("AWS_REGION")

    # Check that all arguments are passed 
    mandatory_args = [('secret key', secret_key), ('access key', access_key), ('region', region)]
    for (arg_name, arg_val) in mandatory_args:
        if arg_val is None:
            logging.error(f"Missing argument: {arg_name}. You can specify it by command line arguments or environment variables, see --help")
            exit(1)
    
    # If no show and no output file, do nothing 
    if args.show and args.output_file is None:
        return
    
    discovery = ECSDiscovery(region, secret_key, access_key) # type: ignore
    services = discovery.list_services()

    if args.show:
        for service in services:
            logging.info(f"[Cluster {service.cluster}] ({service.container_name}) {service.private_ip}:{service.port}")

    # Save file to disk
    if args.output_file is not None:
        services_json = to_prom_json(services)
        path = Path(args.output_file)
        with path.open("w") as f:
            json.dump(services_json, f)
            

if __name__ == "__main__":
    args = parser.parse_args()
    main(args)
