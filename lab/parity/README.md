# Offline parity lab — `lab.test`

A self-contained, deterministic target so reconFTW **v1 (bash)** and **v2 (Go)** can be
compared against something we control, instead of against a public site that
rate-limits, churns its passive sources and makes every parity verdict arguable
(see `docs/14-OPERATOR-VALIDATION.md` §1 and the nuclei-divergence post-mortem).

Everything binds to **127.0.0.1 only** and no query ever leaves the host:

| piece | what | where |
|---|---|---|
| authoritative DNS | CoreDNS, zone `lab.test`: 30 fixed A records, SRV/MX/TXT, `*.lab.test` wildcard, AXFR allowed; NXDOMAIN for every other name | `coredns/Corefile`, `coredns/lab.test.db` |
| HTTP/HTTPS target | stdlib-Go server, vhost by `Host` header (below); self-signed cert with a fixed SAN list on :443 | `httpd/main.go`, `httpd/Dockerfile` |
| resolvers file | the single line `127.0.0.1` — the only resolver puredns/massdns/dnsx may use | `resolvers.txt` |
| v2 config | TOML template (`@LAB_DIR@` → absolute path at render time), `--config` layer | `lab.toml` |
| v1 config | `reconftw.cfg` overlay template, passed with `./reconftw.sh -f` | `v1-overlay.cfg` |
| ground truth | required / bonus / forbidden sets, see below | `expected/*.txt` |
| driver | up → wait → v2 [→ v1] → set-diff → `out/REPORT.md` | `run.sh` |
| OS resolver hook | route `lab.test` to the lab DNS for the web tools | `system-dns.sh` |
| CI | dispatch-only workflow, v2 only, fails on any FAIL in the report | `.github/workflows/parity-lab.yml` |

## Run it

```bash
# prerequisites: docker (compose v2), go, jq, dig, curl, and the recon tools on PATH:
go run ./cmd/reconftw install --profile core        # subfinder httpx dnsx puredns massdns nuclei gf
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest        # + the four lab pivots
go install github.com/edoardottt/csprecon/cmd/csprecon@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest

# the web tools (httpx/nuclei/katana/ffuf/tlsx) resolve through the OS, so once:
sudo lab/parity/system-dns.sh install     # Linux: dummy iface + resolvectl; macOS: /etc/resolver/lab.test
lab/parity/system-dns.sh check

lab/parity/run.sh                  # v2 only, judged against expected/
lab/parity/run.sh --with-v1        # also bash v1, plus v2-vs-v1 and v1-vs-expected rows
lab/parity/run.sh --mode all       # exercises brute / permut / zone transfer / vulns too
lab/parity/run.sh --render-only    # no docker: render configs + validate the TOML with the v2 loader
lab/parity/run.sh --help           # every flag
```

Suggested Makefile target (not added — the Makefile is unchanged by design):

```make
lab-parity: ## offline v1/v2 parity lab against lab.test (docker required)
	lab/parity/run.sh $(LAB_ARGS)
```

Output lands in `lab/parity/out/` (git-ignored): `REPORT.md`, `report.json`, `v2.log`,
`v1.log`, the rendered configs, the effective v2 config and the v2 workspace under
`out/workspaces/lab.test-4e39717b/`. v1 writes to `Recon/lab.test/` at the repo root
as always. A previous workspace / Recon tree is **moved** to `out/.archive/`, never
deleted (same rule as `scripts/parity-full.sh`: re-running over old checkpoints
fabricates the number).

Exit code: `0` PASS, `1` FAIL, `2` usage/environment error.

## How the offline run finds anything

The lab is offline, so every passive source returns nothing. `run.sh` therefore plants
`expected/seed.txt` — the "passive feed" — where each engine merges passive inputs
(v2: `<workspace>/inputs/passive.labseed.txt`; v1: `Recon/lab.test/.tmp/labseed_subs.txt`).
The seed mixes real names with bogus ones that resolve **only through the wildcard**,
and from there the engines' own stages have to do the work:

| discovery path | exercised stage | what it should find |
|---|---|---|
| seed → resolution | puredns `--wildcard-tests/--wildcard-batch` (v2 `subdomains.active`, v1 `_resolve_domains`) | keep the 13 real seed names, **drop** the 4 wildcard-only names |
| TLS SAN pivot | tlsx over the lab certificate on :443 | `portal auth assets status app` |
| CSP pivot | csprecon on `www.lab.test`'s `Content-Security-Policy` | `static cdn beta` |
| SRV enumeration | `dnsx -srv` against the lab DNS | `ldap sip xmpp` |
| HTML links / NS (bonus tier) | katana crawl (v1 `sub_scraping`), NS delegation | `intranet git ci monitor help ns2` |
| web probe | httpx on 80,443 | every 127.0.0.1 name is live; 127.0.0.2 names are not |
| nuclei default templates | `misconfig.lab.test` content | `expected/findings.txt` |
| ffuf auto-calibration | `soft404.lab.test` | no runaway: every path is a 200 with the same shape |

Address plan in the zone: `127.0.0.1` = live web host, `127.0.0.2` = resolves but
nothing listens, `127.0.0.99` = the wildcard answer (so explicit records are
distinguishable from wildcard hits — that is what makes the filter testable).

## What each vhost exercises

| vhost | content | exercises |
|---|---|---|
| `www.lab.test` / `lab.test` | 15 linkable paths, `/robots.txt` with Disallow entries, `/sitemap.xml`, `/static/app.js` naming `api/assets/beta`, CSP naming `static/cdn/beta`, links to `shop/blog/docs/support/api` and the bonus hosts, `/admin` 403 | crawling, URL extraction, JS scraping, CSP pivot, robots wordlist |
| `soft404.lab.test` | **200 for every path**, near-identical body | ffuf `-ac` (soft-404 calibration), url dedup |
| `misconfig.lab.test` | `/.git/HEAD` + `/.git/config`, `/.env`, `/phpinfo.php`, `/backup/` open listing, `/server-status`, `Server: Apache/2.4.49 … PHP/7.4.3`, `/search?q=` reflected unencoded | nuclei exposures/misconfig/tech templates; reflection probes (Gxss/dalfox in `all`) |
| `api.lab.test` | `/api`, `/api/health`, `/api/users/1` JSON, `/openapi.json` | API/JSON handling, swagger/openapi detection |
| any other `*.lab.test` | generic landing page naming the host | live-host probing of every zone record |

TLS: the certificate's SAN list is exactly
`lab.test www api shop portal auth assets status app` (`tlsSANs` in `httpd/main.go`).

## Ground truth (`expected/`)

| file | role | gate |
|---|---|---|
| `seed.txt` | planted passive feed: 13 real + apex + 4 wildcard-only names | input, not compared |
| `subdomains.txt` | **required** subdomain set for a v2 `recon` pass (24 names: seed-real + TLS + CSP + SRV) | removed-ratio ≤ tolerance |
| `hosts.txt` | **required** live-host set (the 19 required names on 127.0.0.1) | removed-ratio ≤ tolerance |
| `findings.txt` | **required** nuclei template-ids on the misconfig/www vhosts | removed-ratio ≤ tolerance |
| `wildcard_only.txt` | the 4 bogus names; present in any subdomain set = **wildcard leak = FAIL** | hard |
| `subdomains_bonus.txt` | crawl-only / NS names (6); never required, excluded from the v2-vs-v1 diff, reported when found | informational |

The apex `lab.test` is excluded from every set. "Added" items never fail a set
(parity-full semantics); only "removed" (reference-only) items count, and the lab
default tolerance is **0 %** because the target is deterministic — raise it with
`--tolerance` only when deliberately comparing engines with different stage sets.

Comparison logic, verdict words and the removed/added lists in the report are a
straight port of `scripts/parity-full.sh` (`comm` over `LC_ALL=C sort -u` sets,
`OK / FAIL / NO-BASELINE / EMPTY-BOTH`), so the two reports read the same way.

### Freeze `expected/findings.txt` after the first real run

Template ids were chosen from the content the lab serves and the templates' known
matchers (`git-config`, `phpinfo-files`, `http-missing-security-headers`,
`apache-detect`, `robots-txt-endpoint`) but **ids drift between nuclei-templates
releases**. On the first docker run, read `out/workspaces/*/artefacts/findings.jsonl`
(and `Recon/lab.test/nuclei_output/*_json.txt` with `--with-v1`), confirm each id,
edit the file to the observed stable set, and only then treat the findings row as a
gate (and uncomment the `schedule:` block in the workflow).

## Known, intentional v1/v2 differences the lab will show

- v2 `recon` has **no zone-transfer stage** (it lives in the `all` enrichment group)
  while v1 `-r` runs `zonetransfer`; the overlay sets `ZONETRANSFER=false` so the
  `recon` comparison is like-for-like. `--mode all` turns it on for both.
- v2 `recon` probes before it crawls, so the crawl-only names are only found on a
  second pass over the same workspace; v1 crawls inside the subdomain stage. That is
  the bonus tier, and it is excluded from the v2-vs-v1 diff on purpose.
- v1 with `DNS_RESOLVER=auto` may pick dnsx on NAT/Docker hosts, where `-wt` is inert
  without `-wd` and the wildcard-only names **leak**. The overlay pins `puredns`;
  switch it to `dnsx` to reproduce the defect on demand.

## Caveats

- Ports 53/80/443 on 127.0.0.1 must be free (systemd-resolved listens on 127.0.0.53,
  which does not conflict). `LAB_BIND` overrides the bind address, nothing else.
- The run is *offline for the target*, not for the toolchain: in CI the passive
  tools still try their public sources for `lab.test` (and get nothing) and nuclei
  updates its templates. Local tool installs are the operator's job.
- The v2 loader still merges `~/.config/reconftw/config.toml` and `./reconftw.toml`
  beneath `--config`; every key the lab cares about is set in `lab.toml`, and
  `run.sh --render-only` writes the effective merge to `out/config.effective.toml`
  so you can check what actually applied.
