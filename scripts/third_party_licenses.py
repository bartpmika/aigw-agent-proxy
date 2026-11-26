"""Writes THIRD_PARTY_LICENSES.txt from `cargo metadata` (stdin): every crate
in the full build with its declared license and license files."""
import glob, json, os, sys

d = json.load(sys.stdin)
pkgs = sorted((p for p in d["packages"] if p["name"] != "aigw-agent-proxy"), key=lambda p: (p["name"], p["version"]))
out = ["Third-party software in aigw-agent-proxy builds", "=" * 48, ""]
for p in pkgs:
    out.append("%s %s  (%s)  %s" % (p["name"], p["version"], p.get("license") or "see license file", p.get("repository") or ""))
out.append("")
for p in pkgs:
    root = os.path.dirname(p["manifest_path"])
    files = sorted(set(sum((glob.glob(os.path.join(root, pat)) for pat in ("LICEN[CS]E*", "COPYING*", "NOTICE*")), [])))
    if not files:
        continue
    out += ["", "-" * 78, "%s %s" % (p["name"], p["version"]), "-" * 78]
    for f in files:
        with open(f, encoding="utf-8", errors="replace") as fh:
            out += ["[%s]" % os.path.basename(f), fh.read().rstrip(), ""]
with open("THIRD_PARTY_LICENSES.txt", "w") as fh:
    fh.write("\n".join(out) + "\n")
print(len(pkgs), "crates")
