#!/usr/bin/env python3
"""Builds the split list's bundled data (DESIGN.md §26.13).

  geosite.txt  v2fly/domain-list-community (MIT), every list resolved:
               includes (with @attr / @-attr filters) and &affiliations
               expanded, one rule per line under "[name]":
               "d:example.com" (domain and subdomains), "f:" full name,
               "k:" keyword, "r:" regular expression; attributes follow
               as " @cn" etc. so "geosite:name@attr" can filter.
  geoip-cn.txt China mainland IPv4 blocks from APNIC's delegation file
               (public statistics), merged into CIDRs, one per line.

Usage: scripts/make-geo-data.py <domain-list-community dir> <delegated-apnic-latest> <out dir>
(the App bundles <out dir> = Sources/App/GeoData; refresh by re-running).
"""
import ipaddress
import os
import re
import sys

sys.dont_write_bytecode = True


def parse(data_dir):
    lists, affiliations = {}, {}
    for name in sorted(os.listdir(data_dir)):
        rules, includes = [], []
        for raw in open(os.path.join(data_dir, name), encoding="utf-8"):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            head, extras = parts[0], parts[1:]
            attrs = [e[1:] for e in extras if e.startswith("@")]
            if head.startswith("include:"):
                must = [a for a in attrs if not a.startswith("-")]
                must_not = [a[1:] for a in attrs if a.startswith("-")]
                includes.append((head[8:].lower(), must, must_not))
                continue
            kind, value = "d", head
            for prefix, k in (("domain:", "d"), ("full:", "f"), ("keyword:", "k"), ("regexp:", "r")):
                if head.startswith(prefix):
                    kind, value = k, head[len(prefix):]
            if kind != "r":
                value = value.lower()
            rule = (kind, value, tuple(sorted(attrs)))
            rules.append(rule)
            for e in extras:
                if e.startswith("&"):
                    affiliations.setdefault(e[1:].lower(), []).append(rule)
        lists[name.lower()] = (rules, includes)
    for target, rules in affiliations.items():
        own, inc = lists.get(target, ([], []))
        lists[target] = (own + rules, inc)
    return lists


def resolve(lists):
    done = {}

    def get(name, stack=()):
        if name in done:
            return done[name]
        if name in stack or name not in lists:
            return []
        rules, includes = lists[name]
        out = list(rules)
        for inc, must, must_not in includes:
            for r in get(inc, stack + (name,)):
                if all(a in r[2] for a in must) and not any(a in r[2] for a in must_not):
                    out.append(r)
        seen, unique = set(), []
        for r in out:
            if r not in seen:
                seen.add(r)
                unique.append(r)
        done[name] = unique
        return unique

    return {name: get(name) for name in sorted(lists)}


def geoip_cn(path):
    nets = []
    for line in open(path, encoding="ascii", errors="ignore"):
        p = line.strip().split("|")
        if len(p) >= 7 and p[1] == "CN" and p[2] == "ipv4" and p[6] in ("allocated", "assigned"):
            start = ipaddress.IPv4Address(p[3])
            end = ipaddress.IPv4Address(int(start) + int(p[4]) - 1)
            nets.extend(ipaddress.summarize_address_range(start, end))
    return list(ipaddress.collapse_addresses(nets))


def main():
    dlc, apnic, out = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(out, exist_ok=True)
    resolved = resolve(parse(os.path.join(dlc, "data")))
    with open(os.path.join(out, "geosite.txt"), "w", encoding="utf-8") as f:
        for name, rules in resolved.items():
            f.write("[" + name + "]\n")
            for kind, value, attrs in rules:
                f.write(kind + ":" + value + "".join(" @" + a for a in attrs) + "\n")
    cn = geoip_cn(apnic)
    with open(os.path.join(out, "geoip-cn.txt"), "w", encoding="ascii") as f:
        for net in cn:
            f.write(str(net) + "\n")
    print("geosite lists:", len(resolved), "rules:", sum(map(len, resolved.values())), "geoip:cn CIDRs:", len(cn))


if __name__ == "__main__":
    main()
