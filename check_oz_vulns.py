#!/usr/bin/env python3
"""
OpenZeppelin Vulnerability Scanner (v2)

Accepts a GitHub branch/directory URL (no filename) or a local path,
searches for the following manifest files:
    • package.json          — npm declarations
    • package-lock.json     — npm resolved versions (if present)
    • yarn.lock             — Yarn v1 (classic) and v2+ (Berry) resolved versions
    • pnpm-lock.yaml        — pnpm v5 / v6 / v9 resolved versions
    • foundry.toml          — Foundry / Soldeer config
    • remappings.txt        — Foundry remappings (OZ git-submodule detection)
Plus .gitmodules — used to resolve the OZ submodule SHA when present.

The vulnerability database is loaded once at startup from an external JSON
file (--db, defaults to oz_vuln_db.json next to this script).

Supported URL formats:
    https://github.com/owner/repo
    https://github.com/owner/repo/tree/<branch|tag|sha>
    https://github.com/owner/repo/tree/<ref>/<subpath>
    ./local/path/to/project

Set GH_TOKEN (or GITHUB_TOKEN) environment variable to raise the GitHub
API rate limit from 60 to 5000 req/hour and to access private repositories.

Usage:
    python check_oz_vulns.py URL [URL ...]
    python check_oz_vulns.py --db custom_db.json URL
    python check_oz_vulns.py -f sources.txt --json > report.json
    python check_oz_vulns.py ./my-project

Exit codes:
    0 — no vulnerabilities found
    1 — vulnerabilities found
    2 — access / parsing errors
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Tuple, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
class C:
    RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for a in ("RED", "YELLOW", "GREEN", "BLUE", "CYAN", "MAGENTA",
                  "BOLD", "DIM", "RESET"):
            setattr(cls, a, "")


# ===========================================================================
# Version & range parsing
# ===========================================================================

Version = Tuple[int, int, int]
Range = Tuple[Version, Optional[Version]]
ANY_RANGE: Range = ((0, 0, 0), None)


def parse_version(v: str) -> Version:
    """Parse 'X.Y.Z' (with optional 'v' prefix / pre-release / build meta) → (X, Y, Z)."""
    v = v.strip().lstrip("v=")
    v = v.split("-", 1)[0].split("+", 1)[0]
    nums = re.findall(r"\d+", v)
    if not nums:
        return (0, 0, 0)
    out = [int(n) for n in nums[:3]]
    while len(out) < 3:
        out.append(0)
    return (out[0], out[1], out[2])


def _caret_max(v: Version) -> Version:
    """Upper bound for npm caret (^) ranges."""
    if v[0] > 0:
        return (v[0] + 1, 0, 0)
    if v[1] > 0:
        return (0, v[1] + 1, 0)
    return (0, 0, v[2] + 1)


def parse_range(spec: str) -> List[Range]:
    """Parse an npm version spec into a list of [min_inclusive, max_exclusive) ranges."""
    spec = (spec or "").strip()
    if not spec or spec == "*" or spec.lower() == "latest":
        return [ANY_RANGE]

    # Git / file / URL references
    if any(t in spec for t in ("github:", "git+", "file:", "http://", "https://")):
        m = re.search(r"#v?(\d+\.\d+(?:\.\d+)?)", spec)
        if m:
            v = parse_version(m.group(1))
            return [(v, (v[0], v[1], v[2] + 1))]
        return [ANY_RANGE]

    # OR alternatives: "1.x || 2.x"
    if "||" in spec:
        out: List[Range] = []
        for sub in spec.split("||"):
            out.extend(parse_range(sub))
        return out

    # Hyphen range: "1.2.3 - 2.3.4"
    if " - " in spec:
        lo, hi = spec.split(" - ", 1)
        lo_v = parse_version(lo); hi_v = parse_version(hi)
        return [(lo_v, (hi_v[0], hi_v[1], hi_v[2] + 1))]

    # AND (space-separated): ">=4.0.0 <5.0.0"
    tokens = spec.split()
    if len(tokens) > 1:
        lo: Version = (0, 0, 0); hi: Optional[Version] = None
        for tok in tokens:
            sub = parse_range(tok)
            if not sub:
                continue
            s_lo, s_hi = sub[0]
            if s_lo > lo:
                lo = s_lo
            if s_hi is not None and (hi is None or s_hi < hi):
                hi = s_hi
        return [(lo, hi)]

    m = re.match(r"^(\^|~|>=|<=|>|<|=)?\s*(.+)$", spec)
    if not m:
        return [ANY_RANGE]
    op = m.group(1) or "="
    ver_raw = m.group(2).strip()

    # Wildcard: "4.x", "4.*", "4.8.x"
    if re.search(r"[xX*]", ver_raw):
        parts = ver_raw.split(".")
        nums: List[int] = []
        for p in parts:
            if p in ("x", "X", "*", ""):
                break
            try:
                nums.append(int(p))
            except ValueError:
                break
        if not nums:
            return [ANY_RANGE]
        if len(nums) == 1:
            return [((nums[0], 0, 0), (nums[0] + 1, 0, 0))]
        if len(nums) == 2:
            return [((nums[0], nums[1], 0), (nums[0], nums[1] + 1, 0))]
        return [((nums[0], nums[1], nums[2]),
                 (nums[0], nums[1], nums[2] + 1))]

    v = parse_version(ver_raw)
    if op == "^":  return [(v, _caret_max(v))]
    if op == "~":  return [(v, (v[0], v[1] + 1, 0))]
    if op == ">=": return [(v, None)]
    if op == ">":  return [((v[0], v[1], v[2] + 1), None)]
    if op == "<=": return [((0, 0, 0), (v[0], v[1], v[2] + 1))]
    if op == "<":  return [((0, 0, 0), v)]
    return [(v, (v[0], v[1], v[2] + 1))]


def ranges_intersect(a: Range, b: Range) -> bool:
    """Return True if two half-open intervals [min, max) overlap."""
    a_min, a_max = a; b_min, b_max = b
    if a_max is not None and a_max <= b_min:
        return False
    if b_max is not None and b_max <= a_min:
        return False
    return True


# ===========================================================================
# DB loading
# ===========================================================================

def load_db(path: str) -> List[dict]:
    """Load and validate the vulnerability database JSON file."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if "vulnerabilities" not in data:
        raise ValueError("DB JSON must contain top-level 'vulnerabilities' array")
    return data["vulnerabilities"]


OZ_PACKAGES = ("@openzeppelin/contracts", "@openzeppelin/contracts-upgradeable")

# Soldeer / submodule package names → canonical npm name
NAME_ALIASES = {
    "@openzeppelin-contracts":             "@openzeppelin/contracts",
    "openzeppelin-contracts":              "@openzeppelin/contracts",
    "@openzeppelin-contracts-upgradeable": "@openzeppelin/contracts-upgradeable",
    "openzeppelin-contracts-upgradeable":  "@openzeppelin/contracts-upgradeable",
}


def canonical_name(name: str) -> str:
    """Resolve Soldeer / submodule alias to the canonical npm package name."""
    return NAME_ALIASES.get(name, name)


# ===========================================================================
# GitHub URL parsing & fetch
# ===========================================================================

@dataclass
class RepoLoc:
    owner: str
    repo: str
    ref: Optional[str]   # branch / tag / sha; None = use default branch
    subpath: str         # "" for repo root, or e.g. "packages/contracts"


def parse_github_url(url: str) -> Optional[RepoLoc]:
    """Parse a GitHub branch/tree URL into a RepoLoc. Returns None on mismatch."""
    u = url.strip().rstrip("/")
    if not u.lower().startswith(("http://", "https://")):
        u = "https://" + u
    m = re.match(
        r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+?)"
        r"(?:/tree/([^/]+)(?:/(.+))?)?/?$",
        u,
    )
    if not m:
        return None
    owner, repo, ref, sub = m.groups()
    return RepoLoc(owner=owner, repo=repo, ref=ref,
                   subpath=(sub or "").strip("/"))


def _gh_request(url: str, accept: str = "*/*", timeout: int = 20) -> bytes:
    """Perform an authenticated GitHub HTTP request."""
    req = Request(url, headers={
        "User-Agent": "oz-scanner/2.0",
        "Accept": accept,
    })
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urlopen(req, timeout=timeout) as r:
        return r.read()


_DEFAULT_BRANCH_CACHE: Dict[Tuple[str, str], str] = {}


def gh_default_branch(loc: RepoLoc) -> str:
    """Fetch and cache the default branch name for a repository."""
    key = (loc.owner, loc.repo)
    if key in _DEFAULT_BRANCH_CACHE:
        return _DEFAULT_BRANCH_CACHE[key]
    url = f"https://api.github.com/repos/{loc.owner}/{loc.repo}"
    raw = _gh_request(url, accept="application/vnd.github+json")
    data = json.loads(raw.decode("utf-8"))
    branch = data.get("default_branch") or "main"
    _DEFAULT_BRANCH_CACHE[key] = branch
    return branch


def gh_fetch_file(loc: RepoLoc, filename: str) -> Optional[str]:
    """Fetch a raw file from raw.githubusercontent.com. Returns None on 404."""
    ref = loc.ref or gh_default_branch(loc)
    path = "/".join(filter(None, [loc.subpath, filename]))
    url = f"https://raw.githubusercontent.com/{loc.owner}/{loc.repo}/{ref}/{path}"
    try:
        return _gh_request(url).decode("utf-8", errors="replace")
    except HTTPError as e:
        if e.code == 404:
            return None
        raise


def gh_get_submodule_sha(loc: RepoLoc, submodule_path: str
                         ) -> Optional[Tuple[str, str]]:
    """Query the GitHub contents API to get (sha, submodule_git_url) for a
    git submodule entry. Returns None if the path is not a submodule or on error."""
    ref = loc.ref or gh_default_branch(loc)
    full = "/".join(filter(None, [loc.subpath, submodule_path]))
    url = (f"https://api.github.com/repos/{loc.owner}/{loc.repo}/contents/"
           f"{full}?ref={ref}")
    try:
        raw = _gh_request(url, accept="application/vnd.github+json")
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, dict) and data.get("type") == "submodule":
            return data.get("sha"), data.get("submodule_git_url", "")
    except HTTPError:
        return None
    except Exception:
        return None
    return None


# ===========================================================================
# Local filesystem source
# ===========================================================================

def is_local_dir(s: str) -> bool:
    return os.path.isdir(s)


def local_read(base: str, filename: str) -> Optional[str]:
    """Read a file from a local directory. Returns None if not found."""
    p = os.path.join(base, filename)
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            return f.read()
    return None


# ===========================================================================
# Findings & audit
# ===========================================================================

@dataclass
class Finding:
    source: str          # 'package.json' / 'package-lock.json' / 'foundry.toml'
    package: str
    declared: str
    exact_version: bool  # True when resolved from lockfile or Soldeer (pinned)
    vuln_id: str
    cve: Optional[str]
    severity: str
    title: str
    affected_range: str
    fixed_in: List[str]


@dataclass
class Note:
    source: str
    level: str           # 'info' / 'warn'
    message: str
    details: Dict = field(default_factory=dict)


def check_vulns(pkg: str, spec: str, source: str, exact: bool,
                vulndb: List[dict]) -> List[Finding]:
    """Check a single package spec against the full vulnerability database."""
    canon = canonical_name(pkg)
    out: List[Finding] = []
    user_ranges = parse_range(spec)
    for v in vulndb:
        if canon not in v["packages"]:
            continue
        hit = None
        for u_r in user_ranges:
            for v_r in v["affected"]:
                vr = (parse_version(v_r[0]), parse_version(v_r[1]))
                if ranges_intersect(u_r, vr):
                    hit = v_r
                    break
            if hit:
                break
        if hit:
            out.append(Finding(
                source=source, package=canon, declared=spec,
                exact_version=exact,
                vuln_id=v["id"], cve=v.get("cve"),
                severity=v["severity"], title=v["title"],
                affected_range=f">={hit[0]} <{hit[1]}",
                fixed_in=list(v["patched"]),
            ))
    return out


def audit_package_json(text: str, vulndb: List[dict]) -> List[Finding]:
    """Scan all dependency sections in package.json against the vuln DB."""
    pkg = json.loads(text)
    out: List[Finding] = []
    for section in ("dependencies", "devDependencies",
                    "peerDependencies", "optionalDependencies"):
        deps = pkg.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if isinstance(spec, str):
                out.extend(check_vulns(name, spec, "package.json", False, vulndb))
    return out


def audit_package_lock(text: str, vulndb: List[dict]) -> List[Finding]:
    """Scan package-lock.json (lockfileVersion 1 nested or 2/3 flat)."""
    lock = json.loads(text)
    out: List[Finding] = []
    lf_version = lock.get("lockfileVersion", 1)

    if lf_version >= 2 and isinstance(lock.get("packages"), dict):
        # v2/v3 — flat list of "node_modules/..." paths
        for path_key, info in lock["packages"].items():
            if not path_key or not isinstance(info, dict):
                continue
            m = re.search(r"node_modules/(@[^/]+/[^/]+|[^/]+)$", path_key)
            if not m:
                continue
            name = m.group(1)
            ver = info.get("version")
            if ver:
                out.extend(check_vulns(name, ver, "package-lock.json",
                                       True, vulndb))
    elif isinstance(lock.get("dependencies"), dict):
        # v1 — recursive structure
        def walk(deps):
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                ver = info.get("version")
                if ver:
                    out.extend(check_vulns(name, ver, "package-lock.json",
                                           True, vulndb))
                if isinstance(info.get("dependencies"), dict):
                    walk(info["dependencies"])
        walk(lock["dependencies"])
    return out


def parse_yarn_lock(text: str) -> List[Tuple[str, str]]:
    """Parse yarn.lock (v1 classic and v2+ Berry).

    Returns deduped (package_name, resolved_version) tuples.

    v1 (classic) entries look like:
        "@openzeppelin/contracts@^4.7.0":
          version "4.7.1"
          resolved "https://..."

    v2+ (Berry) entries use YAML-style colons:
        "@openzeppelin/contracts@npm:^4.7.0":
          version: 4.7.1
          resolution: "@openzeppelin/contracts@npm:4.7.1"
    """
    out: List[Tuple[str, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        # A header line: starts at column 0, ends with ':', not a comment
        if (stripped
                and not line.startswith((" ", "\t", "#"))
                and stripped.endswith(":")):
            header = stripped[:-1]  # drop trailing ':'

            # Parse package names from one or more comma-separated specs.
            pkg_names = set()
            for spec in header.split(","):
                s = spec.strip().strip('"').strip("'")
                if not s:
                    continue
                # Format: "<name>@<rangespec>". The LAST '@' separates them,
                # but a leading '@' (scoped package) must not be split.
                if s.startswith("@"):
                    rest = s[1:]
                    if "@" in rest:
                        name_part, _ = rest.rsplit("@", 1)
                        pkg_names.add("@" + name_part)
                    else:
                        pkg_names.add(s)
                else:
                    if "@" in s:
                        name_part, _ = s.rsplit("@", 1)
                        pkg_names.add(name_part)
                    else:
                        pkg_names.add(s)

            # Look for an indented `version` line in the following block.
            version = None
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip():
                    j += 1
                    continue
                if not nxt.startswith((" ", "\t")):
                    break  # left the block
                # v1: version "4.7.1"   v2+: version: 4.7.1
                m = re.match(r'\s*version\s*:?\s*"?([^"\s]+)"?', nxt)
                if m:
                    version = m.group(1).strip()
                    break
                j += 1

            if version:
                for name in pkg_names:
                    out.append((name, version))
            i = j
            continue
        i += 1

    # Dedupe: identical (name, version) pairs collapse to one
    return list(set(out))


def audit_yarn_lock(text: str, vulndb: List[dict]) -> List[Finding]:
    """Scan yarn.lock against the vuln DB."""
    out: List[Finding] = []
    for name, version in parse_yarn_lock(text):
        out.extend(check_vulns(name, version, "yarn.lock", True, vulndb))
    return out


# --- pnpm-lock.yaml --------------------------------------------------------

def _split_pnpm_key(raw_key: str) -> Optional[Tuple[str, str]]:
    """Split a pnpm `packages:` key into (name, version).

    Handles:
        '/@scope/name@1.2.3'                     (v6+)
        '/@scope/name/1.2.3'                     (v5)
        '/name@1.2.3'
        '@scope/name@1.2.3'                      (v9, no leading slash)
        '/@scope/name@1.2.3(peer@1.0.0)'         (v6+ with peer suffix)
        '/@scope/name/1.2.3_peer@1.0.0'          (v5 with peer suffix)
    """
    s = raw_key.strip()
    # 1. Drop trailing ':' first, THEN trailing/leading quotes (order matters).
    if s.endswith(":"):
        s = s[:-1]
    s = s.strip().strip("'\"").strip()
    if s.startswith("/"):
        s = s[1:]
    # 2. Non-greedy name capture so peer-dep suffixes like (react@18.0.0)
    #    don't get absorbed into the name.
    m = re.match(r'^(.+?)[@/](\d+\.\d+\.\d+[^/@_(]*)', s)
    if not m:
        return None
    return m.group(1), m.group(2)


def parse_pnpm_lock(text: str) -> List[Tuple[str, str]]:
    """Parse pnpm-lock.yaml (v5, v6, v9).

    Returns deduped (package_name, resolved_version) tuples.

    Only the `packages:` section is scanned (it has the full resolved tree).
    Other sections (importers/dependencies/snapshots) are ignored to avoid
    false positives.
    """
    out: List[Tuple[str, str]] = []
    lines = text.splitlines()
    in_packages = False

    for line in lines:
        # Skip blank/comment lines without affecting state
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        # Top-level (column-0) key — enter or leave `packages:` section
        if not line.startswith((" ", "\t")):
            in_packages = line.strip().startswith("packages:")
            continue

        if not in_packages:
            continue

        # Inside `packages:` — match only direct child keys (lines ending in `:`)
        if not line.rstrip().endswith(":"):
            continue

        pair = _split_pnpm_key(line)
        if pair:
            out.append(pair)

    return list(set(out))


def audit_pnpm_lock(text: str, vulndb: List[dict]) -> List[Finding]:
    """Scan pnpm-lock.yaml against the vuln DB."""
    out: List[Finding] = []
    for name, version in parse_pnpm_lock(text):
        out.extend(check_vulns(name, version, "pnpm-lock.yaml", True, vulndb))
    return out


def parse_toml_dependencies(text: str) -> Dict[str, str]:
    """Minimal parser for the [dependencies] section of foundry.toml (Soldeer format)."""
    deps: Dict[str, str] = {}
    in_deps = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            in_deps = (s == "[dependencies]")
            continue
        if not in_deps or "=" not in s:
            continue
        key, val = s.split("=", 1)
        key = key.strip().strip('"').strip("'")
        val = val.strip()
        if val.startswith(('"', "'")):
            deps[key] = val.strip('"').strip("'")
        elif val.startswith("{"):
            mv = re.search(r'version\s*=\s*"([^"]+)"', val)
            if mv:
                deps[key] = mv.group(1)
    return deps


def audit_foundry_toml(text: str, vulndb: List[dict]) -> List[Finding]:
    """Scan Soldeer [dependencies] in foundry.toml against the vuln DB."""
    out: List[Finding] = []
    for key, ver in parse_toml_dependencies(text).items():
        canon = canonical_name(key)
        if canon in OZ_PACKAGES:
            out.extend(check_vulns(canon, ver, "foundry.toml", True, vulndb))
    return out


def parse_remappings(text: str) -> List[Tuple[str, str]]:
    """Extract all remapping lines that reference OpenZeppelin."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        left, right = s.split("=", 1)
        left = left.strip(); right = right.strip()
        if "openzeppelin" in (left + right).lower():
            out.append((left, right))
    return out


def parse_gitmodules(text: str) -> Dict[str, str]:
    """Parse .gitmodules into {submodule_path: url}."""
    out: Dict[str, str] = {}
    cur_path = None; cur_url = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[submodule"):
            if cur_path and cur_url:
                out[cur_path] = cur_url
            cur_path = cur_url = None
        elif s.startswith("path"):
            m = re.match(r"path\s*=\s*(.+)$", s)
            if m: cur_path = m.group(1).strip()
        elif s.startswith("url"):
            m = re.match(r"url\s*=\s*(.+)$", s)
            if m: cur_url = m.group(1).strip()
    if cur_path and cur_url:
        out[cur_path] = cur_url
    return out


# ===========================================================================
# Scan one source
# ===========================================================================

MANIFEST_FILES = ("package.json", "package-lock.json",
                  "yarn.lock", "pnpm-lock.yaml",
                  "foundry.toml", "remappings.txt", ".gitmodules")


@dataclass
class ScanResult:
    source: str
    error: Optional[str] = None
    files_found: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    notes: List[Note] = field(default_factory=list)
    location: Optional[Dict] = None


def scan_source(source: str, vulndb: List[dict],
                resolve_submodules: bool = True) -> ScanResult:
    res = ScanResult(source=source)
    files: Dict[str, Optional[str]] = {}
    loc: Optional[RepoLoc] = None

    # ----- Locate & fetch manifests -----
    if is_local_dir(source):
        for fname in MANIFEST_FILES:
            files[fname] = local_read(source, fname)
        res.location = {"type": "local", "path": os.path.abspath(source)}
    else:
        loc = parse_github_url(source)
        if not loc:
            res.error = ("Invalid GitHub URL. Expected "
                         "https://github.com/owner/repo[/tree/<ref>[/<subpath>]] "
                         "or a path to a local directory.")
            return res
        try:
            for fname in MANIFEST_FILES:
                files[fname] = gh_fetch_file(loc, fname)
        except (HTTPError, URLError) as e:
            res.error = f"network error: {e}"
            return res
        except Exception as e:
            res.error = f"{type(e).__name__}: {e}"
            return res

        res.location = {
            "type": "github",
            "owner": loc.owner, "repo": loc.repo,
            "ref": loc.ref or "(default branch)",
            "subpath": loc.subpath or "(root)",
        }

    found = [f for f, v in files.items()
             if v is not None and f != ".gitmodules"]
    res.files_found = found

    if not found:
        res.error = ("No manifest file found in the specified directory "
                     "(package.json / package-lock.json / yarn.lock / "
                     "pnpm-lock.yaml / foundry.toml / remappings.txt)")
        return res

    # ----- npm / yarn / pnpm audit -----
    pkg_text = files.get("package.json")
    npm_lock_text = files.get("package-lock.json")
    yarn_lock_text = files.get("yarn.lock")
    pnpm_lock_text = files.get("pnpm-lock.yaml")
    any_lockfile = any((npm_lock_text, yarn_lock_text, pnpm_lock_text))

    if pkg_text:
        try:
            res.findings.extend(audit_package_json(pkg_text, vulndb))
        except json.JSONDecodeError as e:
            res.notes.append(Note("package.json", "warn",
                                  f"invalid JSON: {e}"))

    if npm_lock_text:
        try:
            res.findings.extend(audit_package_lock(npm_lock_text, vulndb))
        except json.JSONDecodeError as e:
            res.notes.append(Note("package-lock.json", "warn",
                                  f"invalid JSON: {e}"))

    if yarn_lock_text:
        try:
            res.findings.extend(audit_yarn_lock(yarn_lock_text, vulndb))
        except Exception as e:
            res.notes.append(Note("yarn.lock", "warn",
                                  f"parse error: {e}"))

    if pnpm_lock_text:
        try:
            res.findings.extend(audit_pnpm_lock(pnpm_lock_text, vulndb))
        except Exception as e:
            res.notes.append(Note("pnpm-lock.yaml", "warn",
                                  f"parse error: {e}"))

    # If package.json declares OZ but no lockfile is present, warn that
    # the actually installed version may differ from the declared range.
    if pkg_text and not any_lockfile:
        try:
            pkg = json.loads(pkg_text)
            has_oz = any(canonical_name(n) in OZ_PACKAGES
                         for section in ("dependencies", "devDependencies",
                                         "peerDependencies",
                                         "optionalDependencies")
                         for n in (pkg.get(section) or {}))
            if has_oz:
                res.notes.append(Note(
                    "lockfile", "info",
                    "No lockfile found (package-lock.json / yarn.lock / "
                    "pnpm-lock.yaml) — checking declared ranges only; "
                    "the actually installed version may differ."
                ))
        except json.JSONDecodeError:
            pass

    # ----- Foundry audit -----
    foundry_text = files.get("foundry.toml")
    remap_text = files.get("remappings.txt")
    gitmod_text = files.get(".gitmodules")

    soldeer_known = False
    if foundry_text:
        try:
            soldeer = parse_toml_dependencies(foundry_text)
            soldeer_known = any(canonical_name(k) in OZ_PACKAGES
                                for k in soldeer.keys())
            res.findings.extend(audit_foundry_toml(foundry_text, vulndb))
        except Exception as e:
            res.notes.append(Note("foundry.toml", "warn",
                                  f"parse error: {e}"))

    if remap_text:
        oz_remaps = parse_remappings(remap_text)
        if oz_remaps and not soldeer_known:
            submods = parse_gitmodules(gitmod_text) if gitmod_text else {}
            oz_submods = {p: u for p, u in submods.items()
                          if "openzeppelin" in (p + u).lower()}

            sub_info = []
            for path, url in oz_submods.items():
                entry = {"path": path, "url": url, "sha": None}
                if resolve_submodules and loc is not None:
                    sha_info = gh_get_submodule_sha(loc, path)
                    if sha_info:
                        sha, _ = sha_info
                        entry["sha"] = sha
                        entry["commit_url"] = (
                            f"{url.rstrip('.git')}/commit/{sha}"
                            if url else None
                        )
                sub_info.append(entry)

            res.notes.append(Note(
                "remappings.txt", "warn",
                "Foundry mode: OpenZeppelin is linked as a git submodule. "
                "The exact version CANNOT be determined from remappings alone — "
                "please verify the submodule commit SHA against a release tag manually.",
                details={"remappings": oz_remaps, "submodules": sub_info},
            ))
        elif oz_remaps and soldeer_known:
            res.notes.append(Note(
                "remappings.txt", "info",
                "Foundry remappings to OZ detected; version taken from "
                "[dependencies] in foundry.toml (Soldeer)."
            ))

    return res


# ===========================================================================
# Output
# ===========================================================================

def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """If the same vulnerability is found in both the lockfile (exact) and
    package.json (range), keep the exact one and drop the range duplicate."""
    exact_keys = {(f.vuln_id, f.package) for f in findings if f.exact_version}
    out = []
    for f in findings:
        if (not f.exact_version
                and (f.vuln_id, f.package) in exact_keys):
            continue
        out.append(f)
    return out


SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def sev_color(severity: str) -> str:
    return {
        "Critical": C.RED + C.BOLD,
        "High":     C.RED,
        "Medium":   C.YELLOW,
        "Low":      C.BLUE,
    }.get(severity, "")


def render_text(res: ScanResult) -> None:
    bar = "═" * 80
    print(f"\n{C.BOLD}{bar}{C.RESET}")
    print(f"{C.BOLD}🔎 {res.source}{C.RESET}")
    if res.location:
        if res.location["type"] == "github":
            print(f"   {C.DIM}repo:{C.RESET} "
                  f"{res.location['owner']}/{res.location['repo']}  "
                  f"{C.DIM}ref:{C.RESET} {res.location['ref']}  "
                  f"{C.DIM}path:{C.RESET} {res.location['subpath']}")
        else:
            print(f"   {C.DIM}local:{C.RESET} {res.location['path']}")
    print(f"{C.BOLD}{bar}{C.RESET}")

    if res.error:
        print(f"{C.RED}[ERR]{C.RESET} {res.error}")
        return

    print(f"{C.DIM}Manifests:{C.RESET} "
          f"{', '.join(res.files_found) if res.files_found else '—'}")

    for n in res.notes:
        icon = "⚠ " if n.level == "warn" else "ℹ "
        color = C.YELLOW if n.level == "warn" else C.CYAN
        print(f"\n  {color}{icon}{n.source}:{C.RESET} {n.message}")
        if n.details.get("remappings"):
            for left, right in n.details["remappings"]:
                print(f"      {C.DIM}{left}{C.RESET} → {right}")
        if n.details.get("submodules"):
            for sm in n.details["submodules"]:
                line = f"      submodule: {C.BOLD}{sm['path']}{C.RESET}"
                if sm.get("sha"):
                    line += f"  sha={sm['sha'][:10]}"
                    if sm.get("commit_url"):
                        line += f"  {C.DIM}{sm['commit_url']}{C.RESET}"
                else:
                    line += "  (sha not resolved)"
                print(line)

    if not res.findings:
        # Don't print "OK" when an OZ version could not be determined
        has_warn = any(n.level == "warn" for n in res.notes)
        if has_warn:
            print(f"\n{C.YELLOW}⚠ Scan completed with warnings — "
                  f"the OpenZeppelin version is ambiguous; manual verification required."
                  f"{C.RESET}")
        else:
            print(f"\n{C.GREEN}✓ OK — no vulnerabilities found{C.RESET}")
        return

    findings = dedupe_findings(res.findings)
    findings = sorted(findings,
                      key=lambda f: (SEV_RANK.get(f.severity, 99), f.vuln_id))
    print(f"\n{C.RED}✗ Vulnerabilities found: {len(findings)}{C.RESET}\n")

    for f in findings:
        col = sev_color(f.severity)
        cve = f.cve or "—"
        exact = (f"{C.MAGENTA}[exact]{C.RESET}" if f.exact_version
                 else f"{C.DIM}[range]{C.RESET}")
        print(f"  {col}[{f.severity.upper():8}]{C.RESET} {f.title}")
        print(f"    {C.DIM}ID:{C.RESET} {f.vuln_id}   "
              f"{C.DIM}CVE:{C.RESET} {cve}   "
              f"{C.DIM}source:{C.RESET} {f.source} {exact}")
        print(f"    {C.DIM}Package:{C.RESET} {f.package} "
              f"{C.YELLOW}\"{f.declared}\"{C.RESET}")
        print(f"    {C.DIM}Vulnerable range:{C.RESET} {f.affected_range}"
              f"  →  {C.GREEN}fixed in {', '.join(f.fixed_in)}{C.RESET}")
        print()


def render_json(results: List[ScanResult]) -> None:
    out = []
    for r in results:
        out.append({
            "source": r.source,
            "location": r.location,
            "error": r.error,
            "files_found": r.files_found,
            "notes": [asdict(n) for n in r.notes],
            "findings": [asdict(f) for f in dedupe_findings(r.findings)],
        })
    print(json.dumps(out, indent=2, ensure_ascii=False))


# ===========================================================================
# CLI
# ===========================================================================

def collect_sources(args) -> List[str]:
    out: List[str] = list(args.sources or [])
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    if args.stdin or (not out and not sys.stdin.isatty()):
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    seen = set(); dedup: List[str] = []
    for s in out:
        if s not in seen:
            dedup.append(s); seen.add(s)
    return dedup


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("sources", nargs="*",
                   help="GitHub branch/directory URL or local path")
    p.add_argument("-f", "--file", help="File with one source per line")
    p.add_argument("--stdin", action="store_true",
                   help="Read sources from stdin")
    default_db = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "oz_vuln_db.json")
    p.add_argument("--db", default=default_db,
                   help=f"Path to the vulnerability DB JSON (default: {default_db})")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="Output results as JSON (for CI pipelines)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color output")
    p.add_argument("--no-resolve-submodules", action="store_true",
                   help="Skip GitHub API calls for git submodule SHA resolution")
    args = p.parse_args()

    if args.no_color or not sys.stdout.isatty() or args.as_json:
        C.disable()

    # 1. Load vulnerability DB once at startup
    try:
        vulndb = load_db(args.db)
    except FileNotFoundError:
        print(f"[FATAL] Vulnerability DB not found: {args.db}",
              file=sys.stderr)
        return 2
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[FATAL] Vulnerability DB is invalid: {e}", file=sys.stderr)
        return 2

    sources = collect_sources(args)
    if not sources:
        p.print_help()
        return 2

    if not args.as_json:
        print(f"{C.BOLD}{C.CYAN}OpenZeppelin Vulnerability Scanner v2{C.RESET}")
        print(f"{C.DIM}DB: {args.db}  •  entries: {len(vulndb)}  •  "
              f"sources: {len(sources)}{C.RESET}")
        if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
            print(f"{C.DIM}Tip: set GH_TOKEN to raise the GitHub API limit "
                  f"from 60 to 5000 req/hour{C.RESET}")

    results: List[ScanResult] = []
    total_findings = 0; errors = 0

    for src in sources:
        res = scan_source(src, vulndb,
                          resolve_submodules=not args.no_resolve_submodules)
        results.append(res)
        if res.error:
            errors += 1
        total_findings += len(dedupe_findings(res.findings))
        if not args.as_json:
            render_text(res)

    if args.as_json:
        render_json(results)
    else:
        print(f"\n{C.BOLD}═══ Summary ═══{C.RESET}")
        print(f"Sources:        {len(sources)}")
        print(f"Errors:         {errors}")
        print(f"Findings:       {total_findings}")
        if total_findings == 0 and errors == 0:
            print(f"{C.GREEN}{C.BOLD}All projects are clean ✓{C.RESET}")

    if errors and not total_findings:
        return 2
    return 1 if total_findings else 0


if __name__ == "__main__":
    sys.exit(main())
