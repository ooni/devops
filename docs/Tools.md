
### Geolocation script
The following script can be used to compare the geolocation reported by
the probes submitting measurements compared to the geolocation of the
`/24` subnet the probe is coming from. It is meant to be run on
[backend-fsn.ooni.org](#backend-fsn.ooni.org)&thinsp;🖥.

``` python
##!/usr/bin/env python3

from time import sleep

import systemd.journal
import geoip2.database  # type: ignore

asnfn = "/var/lib/ooniapi/asn.mmdb"
ccfn = "/var/lib/ooniapi/cc.mmdb"
geoip_asn_reader = geoip2.database.Reader(asnfn)
geoip_cc_reader = geoip2.database.Reader(ccfn)


def follow_journal():
    journal = systemd.journal.Reader()
    #journal.seek_tail()
    journal.get_previous()
    journal.add_match(_SYSTEMD_UNIT="nginx.service")
    while True:
        try:
            event = journal.wait(-1)
            if event == systemd.journal.APPEND:
                for entry in journal:
                    yield entry["MESSAGE"]
        except Exception as e:
            print(e)
            sleep(0.1)


def geolookup(ipaddr: str):
    cc = geoip_cc_reader.country(ipaddr).country.iso_code
    asn = geoip_asn_reader.asn(ipaddr).autonomous_system_number
    return cc, asn


def process(rawmsg):
    if ' "POST /report/' not in rawmsg:
        return
    msg = rawmsg.strip().split()
    ipaddr = msg[2]
    ipaddr2 = msg[3]
    path = msg[8][8:]
    tsamp, tn, probe_cc, probe_asn, collector, rand = path.split("_")
    geo_cc, geo_asn = geolookup(ipaddr)
    proxied = 0
    probe_type = rawmsg.rsplit('"', 2)[-2]
    if "," in probe_type:
        return
    if ipaddr2 != "0.0.0.0":
        proxied = 1
        # Probably CloudFront, use second ipaddr
        geo_cc, geo_asn = geolookup(ipaddr2)

    print(f"{probe_cc},{geo_cc},{probe_asn},{geo_asn},{proxied},{probe_type}")


def main():
    for msg in follow_journal():
        if msg is None:
            break
        try:
            process(msg)
        except Exception as e:
            print(e)
            sleep(0.1)


if __name__ == "__main__":
    main()
```


### Test list prioritization monitoring
The following script monitors prioritized test list for changes in URLs
for a set of countries. Outputs StatsS metrics.

> **note**
> The prioritization system has been modified to work on a granularity of
> probe_cc + probe_asn rather than whole countries.

Country-wise changes might be misleading. The script can be modified to
filter for a set of CCs+ASNs.

``` python
##!/usr/bin/env python3

from time import sleep
import urllib.request
import json

import statsd  # debdeps: python3-statsd

metrics = statsd.StatsClient("127.0.0.1", 8125, prefix="test-list-changes")

CCs = ["GE", "IT", "US"]
THRESH = 100


def peek(cc, listmap) -> None:
    url = f"https://api.ooni.io/api/v1/test-list/urls?country_code={cc}&debug=True"
    res = urllib.request.urlopen(url)
    j = json.load(res)
    top = j["results"][:THRESH]  # list of dicts
    top_urls = set(d["url"] for d in top)

    if cc in listmap:
        old = listmap[cc]
        changed = old.symmetric_difference(top_urls)
        tot_cnt = len(old.union(top_urls))
        changed_ratio = len(changed) / tot_cnt * 100
        metrics.gauge(f"-{cc}", changed_ratio)

    listmap[cc] = top_urls


def main() -> None:
    listmap = {}
    while True:
        for cc in CCs:
            try:
                peek(cc, listmap)
            except Exception as e:
                print(e)
            sleep(1)
        sleep(60 * 10)


if __name__ == "__main__":
    main()
```

### Recompressing postcans on S3
The following script can be used to compress .tar.gz files in the S3 data bucket.
It keeps a copy of the original files locally as a backup.
It terminates once a correctly compressed file is found.
Running the script on an AWS host close to the S3 bucket can significantly
speed up the process.

Tested with the packages:

  * python3-boto3  1.28.49+dfsg-1
  * python3-magic  2:0.4.27-2

Set the ACCESS_KEY and SECRET_KEY environment variables.
Update the PREFIX variable as needed.

```python
##!/usr/bin/env python3
from os import getenv, rename
from sys import exit
import boto3
import gzip
import magic

BUCKET_NAME = "ooni-data-eu-fra-test"
## BUCKET_NAME = "ooni-data-eu-fra"
PREFIX = "raw/2021"

def fetch_files():
    s3 = boto3.client(
        "s3",
        aws_access_key_id=getenv("ACCESS_KEY"),
        aws_secret_access_key=getenv("SECRET_KEY"),
    )
    cont_token = None
    while True:
        kw = {} if cont_token is None else dict(ContinuationToken=cont_token)
        r = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=PREFIX, **kw)
        cont_token = r.get("NextContinuationToken", None)
        for i in r.get("Contents", []):
            k = i["Key"]
            if k.endswith(".tar.gz"):
                fn = k.rsplit("/", 1)[-1]
                s3.download_file(BUCKET_NAME, k, fn)
                yield k, fn
        if cont_token is None:
            return

def main():
    s3res = session = boto3.Session(
        aws_access_key_id=getenv("ACCESS_KEY"),
        aws_secret_access_key=getenv("SECRET_KEY"),
    ).resource("s3")
    for s3key, fn in fetch_files():
        ft = magic.from_file(fn)
        if "tar archive" not in ft:
            print(f"found {ft} at {s3key}")
            # continue   # simply ignore already compressed files
            exit()      # stop when compressed files are found
        tarfn = fn[:-3]
        rename(fn, tarfn)  # keep the local file as a backup
        with open(tarfn, "rb") as f:
            inp = f.read()
            comp = gzip.compress(inp, compresslevel=9)
        ratio = len(inp) / len(comp)
        del inp
        print(f"uploading {s3key}   compression ratio {ratio}")
        obj = s3res.Object(BUCKET_NAME, s3key)
        obj.put(Body=comp)
        del comp

main()
```
