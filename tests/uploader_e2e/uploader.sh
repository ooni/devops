#!/bin/bash
# Run the uploader under test once. UPLOADER: path to ooni_api_uploader.py; S3_ENDPOINT overrides the endpoint
T=$(cd "$(dirname "$0")" && pwd); WORK=${WORK:-$T/work}; DOCKER=${DOCKER:-docker}
$DOCKER run --rm --network uploader-e2e --user root -v $WORK/spool:/var/lib/ooniapi/measurements:z \
  -v $T/conf/api-uploader.conf:/etc/ooni/api-uploader.conf:ro,z -v $T/run_uploader.py:/w/run_uploader.py:ro,z \
  -v $UPLOADER:/u.py:ro,z -e S3_ENDPOINT=${S3_ENDPOINT:-http://uploader-e2e-minio:9000} \
  ${UPLOADER_IMAGE:-ooni-uploader-e2e} python3 /w/run_uploader.py /u.py
