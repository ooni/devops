#!/usr/bin/env python3
"""
List objects in an S3 bucket using boto3.
Configuration is read from environment variables (see defaults below).
"""

import os
import boto3
import json
import requests
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Configuration from environment (set these in your shell)
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")           # required if not using IAM role/profile
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")   # required if not using IAM role/profile
ROLE_ARN = os.getenv("ROLE_ARN")
ROLE_SESSION_NAME = os.getenv("ROLE_SESSION_NAME", "assume-role-session")
ROLE_DURATION_SECONDS = int(os.getenv("ROLE_DURATION_SECONDS", "3600"))  # optional
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")
BUCKET_NAME = os.getenv("S3_BUCKET_NAME")                    # required
PREFIX = os.getenv("S3_PREFIX", "")
MAX_KEYS = int(os.getenv("S3_MAX_KEYS", "1000"))
DEST_ROOT = os.getenv("DOWNLOAD_ROOT", "./s3-downloads")
FASTPATH_API = os.getenv("FASTPATH_API", "")

def assume_role_and_get_credentials(role_arn, session_name, duration_seconds=3600):
    """
    Assume the given role and return temporary credentials dict:
    { aws_access_key_id, aws_secret_access_key, aws_session_token }
    """
    # Use provided long-term creds or default chain to call STS
    sts_kwargs = {"region_name": AWS_REGION,
                  "aws_access_key_id": AWS_ACCESS_KEY_ID,
                  "aws_secret_access_key": AWS_SECRET_ACCESS_KEY,
                  }
    sts_client = boto3.client("sts", **sts_kwargs)
    resp = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration_seconds
    )
    creds = resp["Credentials"]
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }

def get_s3_client():
    """
    Returns an S3 client. If ROLE_ARN is set, assumes that role first and uses
    the temporary credentials. Otherwise uses provided credentials or default chain.
    """
    client_kwargs = {"region_name": AWS_REGION}
    if ROLE_ARN:
        try:
            temp = assume_role_and_get_credentials(ROLE_ARN, ROLE_SESSION_NAME, ROLE_DURATION_SECONDS)
            client_kwargs.update(temp)
        except ClientError as e:
            print(f"Error assuming role: {e.response.get('Error', {}).get('Message')}")
            raise
    else:
        if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            client_kwargs.update({
                "aws_access_key_id": AWS_ACCESS_KEY_ID,
                "aws_secret_access_key": AWS_SECRET_ACCESS_KEY,
            })
            if AWS_SESSION_TOKEN:
                client_kwargs["aws_session_token"] = AWS_SESSION_TOKEN
    return boto3.client("s3", **client_kwargs)

def walk(s3, bucket_name, start_prefix=''):
    """
    Generator like os.walk:
    yields (prefix, subprefixes, objects)
      - prefix: current prefix ('' or ending with '/')
      - subprefixes: list of child prefixes (each ends with '/')
      - objects: list of object keys directly under this prefix (no trailing '/')
    """
    paginator = s3.get_paginator("list_objects_v2")
    page_iter = paginator.paginate(Bucket=bucket_name, Prefix=start_prefix, Delimiter='/')
    subprefixes = []
    objects = []
    for page in page_iter:
        subprefixes.extend([cp["Prefix"] for cp in page.get("CommonPrefixes", [])])
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key == start_prefix:
                continue
            objects.append(key)
    yield start_prefix, subprefixes, objects
    for sub in subprefixes:
        yield from walk(s3, bucket_name, sub)

def safe_local_path(prefix, key):
    # turn S3 key into a local path under DEST_ROOT preserving prefix structure
    rel = key[len(prefix):] if prefix and key.startswith(prefix) else key
    return os.path.join(DEST_ROOT, prefix.replace('/', os.sep), rel.replace('/', os.sep))

def ensure_parent(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def process_postcan(s3, bucket, key, local_path):
    try:
        print("Downloading", key)
        s3.download_file(bucket, key, local_path)
        p = Path(local_path)
        msmt_id = p.stem
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
            assert data['format'] == 'json'
            content = data.get('content')
            endpoint = f"{FASTPATH_API}/{msmt_id}"
            try:
                resp = requests.post(endpoint, json=content, timeout=30)
                resp.raise_for_status()
            except requests.RequestException:
                raise
            assert resp.status_code == 200
            assert resp.content == b""
        # XXX: remove file from s3 if everything went OK
        return key, None
    except Exception as e:
        try:
            if os.path.exists(local_path):
                os.remove(local_path)
        except Exception as remove_err:
            return key, f"remove-failed: {remove_err}; download-failed: {e}"
        return key, str(e)

def main():
    if not BUCKET_NAME:
        print("S3_BUCKET_NAME environment variable is required.")
        return
    s3 = get_s3_client()
    for prefix, subs, objs in walk(s3, BUCKET_NAME, ""):
        print(f"PREFIX: {prefix}  subdirs={len(subs)} objects={len(objs)}")
        with ThreadPoolExecutor(max_workers=50) as _exe:
            futures = []
            for key in objs:
                local_path = safe_local_path(prefix, key)
                ensure_parent(local_path)
                futures.append(_exe.submit(process_postcan, s3, BUCKET_NAME, key, local_path))
        
            for fut in as_completed(futures):
                key, err = fut.result()
                if err:
                    print(f"Failed to process {key}: {err}")
                else:
                    print(f"Submitted {key} to fastpath")
            
if __name__ == "__main__":
    main()
