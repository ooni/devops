"""For each hour/cc/test group with overwritten cans, count measurements that exist only in replaced
(noncurrent) versions. Streams public objects from ooni-data-eu-fra; nothing written but the results.
usage: python3 lost_count.py MULTI_VERSIONS_TSV... -> lost_by_group.tsv, lost_uids.tsv"""
import sys, re, csv, io, tarfile, urllib.request, urllib.parse, concurrent.futures as cf, collections
B = "https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/"
groups = set()
for fn in sys.argv[1:]:
    for day, key, *_ in csv.reader(open(fn), delimiter="\t"):
        groups.add(key.rsplit("/", 1)[0] + "/")
import time
def fetch(url, timeout):
    for attempt in range(8):
        try:
            return urllib.request.urlopen(url, timeout=timeout).read()
        except Exception:
            if attempt == 7: raise
            time.sleep(2 ** attempt)
def uids_of(key, vid):
    url = B + urllib.parse.quote(key) + "?versionId=" + urllib.parse.quote(vid, safe="")
    data = fetch(url, 300)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        return {m.name.rsplit("/", 1)[-1][:-5] for m in t.getmembers() if m.name.endswith(".post")}
def group(prefix):
    x = fetch(B + "?" + urllib.parse.urlencode({"versions": "", "prefix": prefix}), 120).decode()
    assert "<IsTruncated>false</IsTruncated>" in x, prefix
    cur, old_union, seen = set(), set(), set()
    for v in re.findall(r"<Version>(.*?)</Version>", x, re.S):
        k = re.search(r"<Key>(.*?)</Key>", v).group(1)
        if not k.endswith(".tar.gz"): continue
        vid = re.search(r"<VersionId>(.*?)</VersionId>", v).group(1); size = re.search(r"<Size>(\d+)</Size>", v).group(1)
        latest = re.search(r"<IsLatest>(.*?)</IsLatest>", v).group(1) == "true"
        if latest: cur |= uids_of(k, vid)
        elif (k, size) not in seen: seen.add((k, size)); old_union |= uids_of(k, vid)
    return prefix, cur, old_union - cur
import os
done = set()
if os.path.exists("lost_by_group.tsv"):
    done = {l.split("\t")[0] for l in open("lost_by_group.tsv")}
groups = groups - done
print("groups already done", len(done), "remaining", len(groups), flush=True)
with open("lost_by_group.tsv", "a") as g, open("lost_uids.tsv", "a") as u, cf.ThreadPoolExecutor(8) as ex:
    tot = 0
    for i, (prefix, cur, lost) in enumerate(ex.map(group, sorted(groups))):
        tot += len(lost); g.write(f"{prefix}\t{len(cur)}\t{len(lost)}\n")
        for x in sorted(lost): u.write(f"{prefix}\t{x}\n")
        if i % 200 == 0: print(i, "groups done, lost so far", tot, flush=True)
    print("groups", len(groups), "lost (only in replaced versions)", tot)
