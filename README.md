# OpenZeppelin Vulnerability Scanner v2

Scans Hardhat and Foundry projects for known vulnerabilities in
`@openzeppelin/contracts` and `@openzeppelin/contracts-upgradeable`.

## Files

| File | Purpose |
|---|---|
| `check_oz_vulns.py` | Scanner script |
| `oz_vuln_db.json` | External vulnerability database (loaded once at startup) |

## Requirements

Python 3.8+, no third-party dependencies.  
Place both files in the same directory.

## What it checks

The scanner searches for four manifest files in the specified branch/directory
and audits each one when present:

| File | Version source | Precision |
|---|---|---|
| `package.json` | Declared npm ranges | Approximate (`^4.7.0`) |
| `package-lock.json` | Resolved installed versions | **Exact** (takes priority) |
| `foundry.toml` | Soldeer `[dependencies]` | **Exact** |
| `remappings.txt` + `.gitmodules` | git submodule path | SHA commit — requires manual tag lookup |

When the same CVE appears in both `package-lock.json` (`[exact]`) and
`package.json` (`[range]`), the duplicate range finding is discarded and
only the exact one is reported.

Range findings that do not apply to the currently installed version are kept
as a signal that running `npm update` could introduce the vulnerability.

## Usage

```bash
# One or more branch/directory URLs
python3 check_oz_vulns.py \
  https://github.com/owner/repo \
  https://github.com/owner/repo/tree/dev \
  https://github.com/owner/repo/tree/v1.0/packages/contracts

# From a file (one URL per line, # lines are comments)
python3 check_oz_vulns.py -f sources.txt

# Local directory (useful in CI before push)
python3 check_oz_vulns.py ./

# JSON output for CI pipelines
python3 check_oz_vulns.py -f sources.txt --json > report.json

# Custom vulnerability DB
python3 check_oz_vulns.py --db /path/to/custom_db.json https://github.com/foo/bar

# Skip GitHub API calls for submodule SHA resolution
python3 check_oz_vulns.py --no-resolve-submodules https://github.com/foo/bar

# Disable ANSI colors (auto-disabled when piping or using --json)
python3 check_oz_vulns.py --no-color ./my-project
```

### GitHub token

Without a token the GitHub API allows 60 requests/hour per IP.
With a token the limit rises to 5000/hour and private repositories are accessible:

```bash
export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
python3 check_oz_vulns.py https://github.com/private-org/private-repo
```

Both `GH_TOKEN` and `GITHUB_TOKEN` are recognised.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All sources are clean |
| `1` | Vulnerabilities found |
| `2` | Access / parsing / DB errors |

## Vulnerability DB format (`oz_vuln_db.json`)

```json
{
  "schema_version": "1.0",
  "updated_at": "YYYY-MM-DD",
  "source": "https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories",
  "vulnerabilities": [
    {
      "id": "GHSA-...",
      "cve": "CVE-...",
      "severity": "Critical | High | Medium | Low",
      "title": "Short description",
      "packages": ["@openzeppelin/contracts", "@openzeppelin/contracts-upgradeable"],
      "affected": [["3.3.0", "3.4.2"], ["4.0.0", "4.3.1"]],
      "patched":  ["3.4.2", "4.3.1"]
    }
  ]
}
```

**Field notes:**

- `affected`: list of half-open intervals `[min_inclusive, max_exclusive)`.
  A version `V` is vulnerable when `min <= V < max`.
- `patched`: first safe release for each affected major branch.
- `packages`: canonical npm names only. Soldeer and submodule aliases
  (`@openzeppelin-contracts`, `openzeppelin-contracts`, etc.) are resolved
  automatically via `NAME_ALIASES` in the scanner.

## Updating the database

`oz_vuln_db.json` is a plain JSON file — edit it manually or script the update.
Sources to monitor:

- <https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories>
- <https://github.com/advisories?query=openzeppelin>
- GitHub Security Advisory API: `GET /repos/OpenZeppelin/openzeppelin-contracts/security-advisories`

A weekly cron job that checks for new advisories and sends an alert is
recommended but is outside the scope of this script.

## Known limitations

1. **Submodule version is not auto-resolved.** The scanner can retrieve the
   commit SHA via the GitHub API (`--no-resolve-submodules` skips this), but
   mapping SHA → release tag requires an additional lookup or manual
   verification in the GitHub UI.

2. **Transitive dependencies in range mode.** Without a lockfile only
   top-level declarations are visible. `package-lock.json` exposes the full
   resolved dependency tree.

3. **Yarn lock / pnpm lock not supported.** Only `package-lock.json` v1/v2/v3
   is parsed. Yarn and pnpm support can be added following the same pattern.

4. **Pre-release suffixes are stripped.** `4.9.4-rc.0` is treated as `4.9.4`.

## Example output

```
════════════════════════════════════════════════════════════════════════════════
🔎 https://github.com/foo/old-defi/tree/main
   repo: foo/old-defi  ref: main  path: (root)
════════════════════════════════════════════════════════════════════════════════
Manifests: package.json, package-lock.json

✗ Vulnerabilities found: 9

  [HIGH    ] ECDSA signature malleability (EIP-2098 compact sigs)
    ID: GHSA-4h98-2769-gh6h   CVE: CVE-2022-35961   source: package-lock.json [exact]
    Package: @openzeppelin/contracts "4.7.1"
    Vulnerable range: >=4.1.0 <4.7.3  →  fixed in 4.7.3

  [HIGH    ] MerkleProof: multiproof forgery
    ID: GHSA-wprv-93r4-jj2p   CVE: —   source: package-lock.json [exact]
    Package: @openzeppelin/contracts "4.7.1"
    Vulnerable range: >=4.7.0 <4.9.2  →  fixed in 4.9.2
  ...

═══ Summary ═══
Sources:        3
Errors:         0
Findings:       12
```
