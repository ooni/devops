#!/bin/bash
# Run a reuploader version (ooni/backend reuploader/src/reuploader/main.py) once against the failed bucket.
T=$(cd "$(dirname "$0")" && pwd); DOCKER=${DOCKER:-docker}
$DOCKER run --rm --network uploader-e2e -v $1:/r.py:ro,z \
  -e S3_BUCKET_NAME=e2e-failed -e FASTPATH_API=http://uploader-e2e-fastpath:8472 -e BATCH_SIZE=1000 -e LOG_LEVEL=INFO \
  -e AWS_ENDPOINT_URL=http://uploader-e2e-minio:9000 -e AWS_ACCESS_KEY_ID=e2eadmin -e AWS_SECRET_ACCESS_KEY=e2esecret123 \
  -e AWS_REGION=us-east-1 $FASTPATH_IMAGE python /r.py
