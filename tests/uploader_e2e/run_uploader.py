"""Run an ooni_api_uploader.py once against the test environment, without changing it: log to stdout
(no journald in the container) and point its S3 client at the test endpoint (the hosts' boto3 1.20
ignores AWS_ENDPOINT_URL). usage: run_uploader.py UPLOADER_FILE"""
import importlib.util, logging, os, sys
import boto3

spec = importlib.util.spec_from_file_location("uploader", sys.argv[1])
up = importlib.util.module_from_spec(spec)
spec.loader.exec_module(up)
for h in list(up.log.handlers):
    up.log.removeHandler(h)
h = logging.StreamHandler(sys.stdout)
h.setFormatter(logging.Formatter("%(asctime)s uploader %(levelname)s %(message)s"))
up.log.addHandler(h)

def create_s3_client(conf):
    session = boto3.Session(aws_access_key_id=conf.get("aws_access_key_id"), aws_secret_access_key=conf.get("aws_secret_access_key"))
    return session.resource("s3", endpoint_url=os.environ["S3_ENDPOINT"], region_name="us-east-1")

up.create_s3_client = create_s3_client
up.main()
