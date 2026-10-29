# Third-party data shipped in this repository

reconFTW's own code is MIT (see `LICENSE`). The repository also vendors a small
set of data files that originate elsewhere. This file records what each one is,
where it came from and under which licence, as far as that can be determined
from the file headers, the installer history or well-known provenance.
**Nothing here is inferred**: an unknown licence is written as unknown.

The ~100 external tools reconFTW orchestrates are *not* vendored — they are
installed on the host by `reconftw install` (v2, from
`internal/core/backend/tools.lock`) or `install.sh` (v1, from `tools.lock`) and
keep their own licences.

## `data/wordlists/`

Listed file by file in [`data/wordlists/SOURCES.md`](data/wordlists/SOURCES.md).
Summary: five lists are maintainer-authored (MIT), `fuzz_wordlist.txt` comes
from the maintainer's OneListForAll aggregate, `lfi_wordlist.txt` from a public
gist, and `subdomains.txt` has **no recorded origin — maintainer to confirm**.

## `data/patterns/`

| File | Used by | Origin | Licence |
|---|---|---|---|
| `jsluice_patterns.json` | `web.jsluice` secrets scan (`jsluice secrets --patterns`) / v1 `jschecks()` | Gist `six2dez/2aafa8dc2b682bb0081684e71900e747`, which the v1 installer downloaded as `jsluice_patterns.json` before it was vendored (commit `425a550e`). The pattern format is [BishopFox/jsluice](https://github.com/BishopFox/jsluice)'s; individual regexes resemble widely circulated secret-detection rules (gitleaks / trufflehog style) and the file carries no attribution header. | **Origin of the individual patterns unrecorded — maintainer to confirm.** The gist is maintainer-owned; the upstream of each regex is not documented. |

## `templates/`

| File | Used by | Origin | Licence |
|---|---|---|---|
| `services.json` | `osint.misconfig` / v1 `third_party_misconfigs()` — the service catalogue passed to [intigriti/misconfig-mapper](https://github.com/intigriti/misconfig-mapper) | The file's `references` URLs all point at `bugology.intigriti.io/misconfig-mapper-docs/…`, i.e. it is the `templates/services.json` catalogue distributed with misconfig-mapper, vendored so the scan works without network access to the upstream template feed. | misconfig-mapper's repository licence applies — **not recorded here; maintainer to confirm** the exact licence and the upstream commit this copy matches. |

## `config/*.txt`

`config/sensitive_domains.txt`, `config/ssrf_payloads.txt`, `config/tls_ports.txt`
and `config/uncommon_ports_web.txt` are maintainer-authored (their headers say
so where there is one) and are covered by the project licence (MIT).
`sensitive_domains.txt` credits the DEF CON subdomain-enumeration retrospective
as the source of its recommendations, not of its contents.

## Go module dependencies

Compiled into the v2 binary; see `go.mod` / `go.sum`. Licence notices for those
are the modules' own and can be produced with
`go install github.com/google/go-licenses@latest && go-licenses report ./cmd/reconftw`.
They are not duplicated here.

## Keeping this file honest

Add a row whenever a data file is vendored, with the commit that introduced it.
If you cannot establish the licence, write "unrecorded — maintainer to confirm"
rather than guessing. `data/wordlists/SOURCES.md` follows the same rule.
