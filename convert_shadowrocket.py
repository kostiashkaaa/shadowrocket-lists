#!/usr/bin/env python3
"""Convert itdoginfo/allow-domains lists into Shadowrocket rule sets.

Usage: convert_shadowrocket.py <upstream_dir> <out_dir> <raw_base_url>
"""
import sys
from pathlib import Path

upstream, out, base = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3].rstrip("/")


def read(path):
    if not path.exists():
        return []
    lines = (l.strip() for l in path.read_text(encoding="utf-8").splitlines())
    return [l for l in lines if l and not l.startswith("#")]


def domain_rules(domains):
    return [f"DOMAIN-SUFFIX,{d.lstrip('*.')}" for d in domains]


def subnet_rules(name):
    rules = []
    for ver, kind in (("IPv4", "IP-CIDR"), ("IPv6", "IP-CIDR6")):
        # Upstream has case-duplicates (Meta.lst / meta.lst), merge them
        for f in (upstream / "Subnets" / ver).glob("*.lst"):
            if f.stem.lower() == name:
                rules += [f"{kind},{c},no-resolve" for c in read(f)]
    return rules


def write(rel, rules):
    rules = list(dict.fromkeys(rules))
    path = out / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# Source: https://github.com/itdoginfo/allow-domains\n# Rules: {len(rules)}\n"
                    + "\n".join(rules) + "\n", encoding="utf-8")
    return rel


lists = {}
for region in ("Russia", "Ukraine"):
    for side in ("inside", "outside"):
        domains = read(upstream / region / f"{side}-raw.lst")
        if domains:
            lists[f"{region.lower()}_{side}"] = write(f"{region.lower()}_{side}.list", domain_rules(domains))

for group in ("Services", "Categories"):
    for f in sorted((upstream / group).glob("*.lst")):
        rules = domain_rules(read(f)) + (subnet_rules(f.stem) if group == "Services" else [])
        lists[f.stem] = write(f"{group.lower()}/{f.stem}.list", rules)

# Ready-to-import config: Russia inside + popular services via proxy, rest direct
enabled = ["russia_inside", "youtube", "discord", "telegram", "meta", "twitter", "tiktok", "google_ai"]
rule_lines = []
for name, rel in lists.items():
    prefix = "" if name in enabled else "# "
    rule_lines.append(f"{prefix}RULE-SET,{base}/{rel},PROXY")

conf = f"""# Shadowrocket config generated from https://github.com/itdoginfo/allow-domains
# Uncomment RULE-SET lines below to route more lists through the proxy.
[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32
dns-server = system
ipv6 = false
update-url = {base}/shadowrocket.conf

[Rule]
{chr(10).join(rule_lines)}
FINAL,DIRECT
"""
(out / "shadowrocket.conf").write_text(conf, encoding="utf-8")
print(f"Generated {len(lists)} rule sets in {out}")
