"""Check what the repair changed, against snapshots taken before and after it:
  1. every object version from before still exists unchanged, unless prune deleted it; every deleted
     version was noncurrent and is in prune.log
  2. every object current before is still current, with the same VersionId and ETag
  3. no key that existed before got a new version; the only new objects are restored cans (identity n9)
  4. jsonl rows of measurements the repair did not restore are unchanged; each restored measurement has
     exactly one row, pointing at a restored can
  5. every measurement that reached S3 is served with its own body (check.py); the only ones not found
     are those that never reached S3
usage: compare.py BEFORE.json AFTER.json REPAIR_STATE_DIR CHECK_RESULT.json"""
import collections, json, os, sys

before, after = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
state, result = sys.argv[3], json.load(open(sys.argv[4]))
fails = []
def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails.append(msg)

bv = {(v["key"], v["vid"]): v for v in before["versions"]}
av = {(v["key"], v["vid"]): v for v in after["versions"]}
pruned = set()
if os.path.exists(os.path.join(state, "prune.log")):
    for line in open(os.path.join(state, "prune.log")):
        f = line.rstrip("\n").split("\t")
        pruned.add((f[2], f[3]))
restored_uids = set()
if os.path.exists(os.path.join(state, "restored.tsv")):
    restored_uids = {l.split("\t")[1] for l in open(os.path.join(state, "restored.tsv"))}

gone = set(bv) - set(av)
ok(gone == pruned, f"1. the {len(gone)} versions that disappeared are exactly the {len(pruned)} in prune.log")
ok(all(not bv[k]["latest"] for k in gone), "1. every deleted version was noncurrent")
ok(all(bv[k].get("etag") == av[k].get("etag") for k in set(bv) & set(av)), "1. every remaining version is byte-identical (same ETag)")
cur_before = {k for k, v in bv.items() if v["latest"]}
ok(all(k in av and av[k]["latest"] for k in cur_before), f"2. all {len(cur_before)} objects current before are still current, same VersionId")
keys_before = {k for k, _ in bv}
new = set(av) - set(bv)
ok(all(k not in keys_before for k, _ in new), "3. no key that existed before got a new version")
ok(all(".n9." in k for k, _ in new), f"3. the {len(new)} new objects are all restored cans (.n9.)")

def rows_by_uid(snap):
    d = collections.defaultdict(list)
    for r in snap["jsonl"]:
        d[r[4]].append(tuple(r))
    return d
rb, ra = rows_by_uid(before), rows_by_uid(after)
untouched = [u for u in set(rb) | set(ra) if u not in restored_uids]
ok(all(sorted(rb.get(u, [])) == sorted(ra.get(u, [])) for u in untouched),
   f"4. jsonl rows of the {len(untouched)} measurements not restored are unchanged")
ok(all(len(ra.get(u, [])) == 1 and ".n9." in ra[u][0][2] for u in restored_uids),
   f"4. each of the {len(restored_uids)} restored measurements has one jsonl row, pointing at a restored can")

reached_s3 = {u for v in before["versions"] for u in v.get("uids", [])}
not_found = set(result["bad"].get("not_found", []))
never = not_found - reached_s3
ok(result["results"].get("WRONG BODY (another measurement)", 0) == 0 and not result["bad"].get("missing"),
   "5. no measurement is served with another measurement's body or from a missing file")
ok(not (not_found & reached_s3), f"5. every measurement that reached S3 is found ({result['results'].get('ok', 0)} ok); "
   f"{len(never)} never reached S3 (deleted from the spool before upload by the old uploader)")
ok(not result["replaced"], f"5. no S3 object is left with noncurrent versions ({len(result['replaced'])})")
print("RESULT:", "PASS" if not fails else f"FAIL ({len(fails)} checks)")
sys.exit(1 if fails else 0)
