"""Create the raw bucket (versioned, publicly readable, like ooni-data-eu-fra) and the failed-reports bucket."""
import json, time
import boto3
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:19900", aws_access_key_id="e2eadmin",
                  aws_secret_access_key="e2esecret123", region_name="us-east-1")
for i in range(60):
    try:
        s3.list_buckets(); break
    except Exception:
        time.sleep(1)
for b in ("e2e-raw", "e2e-failed"):
    s3.create_bucket(Bucket=b)
    s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
s3.put_bucket_policy(Bucket="e2e-raw", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::e2e-raw", "arn:aws:s3:::e2e-raw/*"]}]}))
