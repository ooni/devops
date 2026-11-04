"""List object versions under raw/<day>/ in ooni-data-eu-fra (public, read-only) and report keys
with more than one version, i.e. objects overwritten after their first upload.
usage: python3 versions.py FIRST_DAY LAST_DAY  (YYYYMMDD)  -> multi_versions.tsv"""
import sys, re, datetime, urllib.request, urllib.parse, concurrent.futures as cf, collections
B = "https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/"
def day_versions(day):
    out = collections.defaultdict(list); km = vm = None
    while True:
        q = {"versions": "", "prefix": f"raw/{day}/"}
        if km: q["key-marker"] = km; q["version-id-marker"] = vm
        x = urllib.request.urlopen(B + "?" + urllib.parse.urlencode(q), timeout=60).read().decode()
        for v in re.findall(r"<(?:Version|DeleteMarker)>(.*?)</(?:Version|DeleteMarker)>", x, re.S):
            k = re.search(r"<Key>(.*?)</Key>", v).group(1)
            out[k].append((re.search(r"<LastModified>(.*?)</LastModified>", v).group(1),
                           (re.search(r"<Size>(\d+)</Size>", v) or [None, "del"])[1] if "<Size>" in v else "delete-marker",
                           re.search(r"<IsLatest>(.*?)</IsLatest>", v).group(1)))
        if "<IsTruncated>true</IsTruncated>" not in x: break
        km = re.search(r"<NextKeyMarker>(.*?)</NextKeyMarker>", x).group(1)
        vm = re.search(r"<NextVersionIdMarker>(.*?)</NextVersionIdMarker>", x).group(1)
    return day, {k: v for k, v in out.items() if len(v) > 1}, len(out)
d0 = datetime.datetime.strptime(sys.argv[1], "%Y%m%d"); d1 = datetime.datetime.strptime(sys.argv[2], "%Y%m%d")
days = [(d0 + datetime.timedelta(days=i)).strftime("%Y%m%d") for i in range((d1 - d0).days + 1)]
with open("multi_versions.tsv", "w") as f, cf.ThreadPoolExecutor(6) as ex:
    for day, multi, n in ex.map(day_versions, days):
        print(day, "objects", n, "with >1 version", len(multi), flush=True)
        for k, vs in sorted(multi.items()):
            for lm, size, latest in sorted(vs):
                f.write(f"{day}\t{k}\t{lm}\t{size}\t{latest}\n")
