# Filters turning tf/modules/ooniapi_frontend/routes.yaml (shared with the
# ALB) into the gateway's nginx locations; see tasks/main.yml.
#
# nginx picks a location by exact match, then longest prefix, where the ALB
# goes by rule priority. The two agree as long as every ALB pattern is exact
# or a prefix (a trailing *), and no prefix of one service covers a path of
# another; ooniapi_gateway_route_problems lists the routes where they would
# not.


def _locations(routes):
    out = []
    for r in sorted(routes, key=lambda r: r["priority"]):
        # the ALB sends these to ooniprobe_legacy, which the gateway doesn't
        # run: they go to ooniprobe, whatever their X-Protocol-Version
        if r.get("legacy"):
            continue
        for p in r.get("paths", []):
            prefix = p.endswith("*")
            cache = None
            if p in r.get("cache_long", []):
                cache = "long"
            elif r.get("cache"):
                cache = "short"
            out.append({
                "route": r["name"],
                "service": r["service"],
                "match": "^~" if prefix else "=",
                "path": p[:-1] if prefix else p,
                "cache": cache,
            })
    return out


def ooniapi_gateway_locations(routes):
    return _locations(routes)


def ooniapi_gateway_direct_hosts(routes):
    return list(dict.fromkeys(r["service"] for r in routes if r.get("direct_host")))


def ooniapi_gateway_route_problems(routes):
    locations = _locations(routes)
    problems = []
    seen = {}
    for r in routes:
        for p in r.get("cache_long", []):
            if p not in r.get("paths", []):
                problems.append(f"{r['name']}: cache_long {p} is not one of its paths")
    for loc in locations:
        if "*" in loc["path"] or "?" in loc["path"]:
            problems.append(f"{loc['route']}: {loc['path']}: only exact paths and a trailing * can be served by nginx")
        key = (loc["match"], loc["path"])
        if key in seen:
            problems.append(f"{loc['route']}: {loc['path']} is also routed by {seen[key]}")
        seen.setdefault(key, loc["route"])
    for a in locations:
        if a["match"] != "^~":
            continue
        for b in locations:
            if b["service"] != a["service"] and b["path"].startswith(a["path"]):
                problems.append(f"{a['route']}: {a['path']}* covers {b['route']}'s {b['path']}, nginx would not follow ALB priorities")
    return problems


class FilterModule:
    def filters(self):
        return {
            "ooniapi_gateway_locations": ooniapi_gateway_locations,
            "ooniapi_gateway_direct_hosts": ooniapi_gateway_direct_hosts,
            "ooniapi_gateway_route_problems": ooniapi_gateway_route_problems,
        }
