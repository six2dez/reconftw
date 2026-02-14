# reconFTW Architecture

## Overview

reconFTW is a modular reconnaissance framework. The codebase is organized as follows:

```
reconftw/
├── reconftw.sh          # Main entry point, argument parsing, orchestration
├── reconftw.cfg         # Main configuration file (all settings)
├── modules/             # Phase-specific modules (what to do)
│   ├── utils.sh         # Utility functions (cleanup, sanitization, caching)
│   ├── core.sh          # Framework core (logging, tools check, lifecycle)
│   ├── osint.sh         # OSINT gathering functions
│   ├── subdomains.sh    # Subdomain enumeration
│   ├── web.sh           # Web analysis and crawling
│   ├── vulns.sh         # Vulnerability scanning
│   ├── axiom.sh         # Axiom distributed scanning
│   └── modes.sh         # Scan mode orchestration
├── lib/                 # Pure utility libraries (how to do it)
│   ├── config.sh        # [FUTURE] Modular config loader
│   └── validation.sh    # Input validation functions
└── tests/               # Test suite
    ├── unit/            # Unit tests (bats)
    ├── security/        # Security tests
    └── mocks/           # Tool mocks for testing
```

## Module Load Order

Modules are sourced in this specific order (defined in `reconftw.sh`):

1. `modules/utils.sh` - Base utilities (must be first)
2. `modules/core.sh` - Framework infrastructure
3. `modules/osint.sh` - OSINT functions
4. `modules/subdomains.sh` - Subdomain enumeration
5. `modules/web.sh` - Web analysis
6. `modules/vulns.sh` - Vulnerability scanning
7. `modules/axiom.sh` - Distributed scanning
8. `modules/modes.sh` - Mode orchestration (must be last)

## Data Flow

```
Target Input → Sanitization → Phase Execution → Output Files
     ↓              ↓               ↓               ↓
  --domain     sanitize_domain   start_func     Recon/$domain/
  --list       sanitize_ip       [tool calls]   subdomains/
  --cidr                         end_func       webs/vulns/
```

## Key Functions

### Lifecycle Functions (core.sh)
- `start_func(name, description)` - Begin a function, check if already done
- `end_func(message, name)` - Complete a function, mark as done

### Utility Functions (utils.sh)
- `sanitize_domain(domain)` - Sanitize domain input (lowercase, safe chars)
- `sanitize_ip(ip)` - Sanitize IP/CIDR input
- `should_run_deep(count, limit)` - Check if DEEP mode should run
- `deleteOutScoped(scopefile, targetfile)` - Remove out-of-scope entries
- `run_command(cmd, args...)` - Execute with logging (respects DRY_RUN)

### DNS Resolution Functions (utils.sh)

All DNS resolution goes through two global wrappers that auto-select between puredns and dnsx based on the network environment:

- `_get_local_ip()` - Get the primary local IP address (cross-platform). Uses `route -n get default` on macOS and `ip -4 route get 1.1.1.1` on Linux to find the correct interface regardless of naming.
- `_ip_is_public_ipv4(ip)` - Conservative check for publicly routable IPv4. Treats RFC1918, CGNAT (100.64.0.0/10), loopback, link-local, multicast/reserved as non-public.
- `_is_behind_nat()` - Detect if running behind NAT (or unknown network) by checking the primary local IP. Defaults to NAT-safe behavior if detection fails.
- `init_dns_resolver()` - Evaluates resolver selection once per run and caches it in `DNS_RESOLVER_SELECTED` when `DNS_RESOLVER=auto`.
- `_select_dns_resolver()` - Select DNS resolver based on `DNS_RESOLVER` config. `puredns`/`dnsx` force the resolver; `auto` uses the cached selection from `init_dns_resolver()` (with a safe fallback if unset).
- `_resolve_domains(input_file, output_file)` - Resolve a list of domains. Uses puredns (massdns + wildcard filter) on VPS or dnsx (Go net resolver + basic wildcard threshold) behind NAT.
- `_bruteforce_domains(wordlist, target_domain, output_file)` - Bruteforce subdomains. Equivalent to `puredns bruteforce wordlist domain` or `dnsx -d domain -w wordlist`.

**Why two resolvers:** puredns uses massdns which sends raw UDP packets to thousands of resolvers simultaneously. This floods the NAT table on consumer routers and can kill connectivity. dnsx uses Go's standard net resolver through the OS networking stack, which is NAT-friendly but lacks puredns's advanced wildcard detection.

### Permutation Functions (subdomains.sh)

- `_select_permutations_wordlist(source_file)` - Choose wordlist based on `PERMUTATIONS_WORDLIST_MODE` and subdomain count. In `auto` mode: full list (849 words) for <=100 subs or DEEP mode, short list (162 words) for >100 subs.
- `_run_permutation_engine(source_file)` - Run gotator with the auto-selected wordlist.
- `_generate_permutation_candidates(source_file, output_file)` - Generate permutation candidates with byte-size limit.

### Validation Functions (lib/validation.sh)
- `validate_domain(domain)` - Validate domain format
- `validate_ipv4(ip)` - Validate IPv4 address
- `validate_boolean(value)` - Validate boolean string

## Global Variables

### Required (set before module load)
- `$SCRIPTPATH` - Path to reconftw installation
- `$domain` - Target domain
- `$dir` - Output directory for current scan

### Configuration (from reconftw.cfg)
- `$DEEP` - Enable deep/thorough scanning
- `$DEEP_LIMIT` - Threshold for auto-deep mode
- `$AXIOM` - Enable distributed scanning
- `$*_THREADS` - Thread counts per tool
- `$DNS_RESOLVER` - DNS resolver selection (`auto`|`puredns`|`dnsx`)
- `$DNS_RESOLVER_SELECTED` - Cached resolver selection for this run (set by `init_dns_resolver()` when `DNS_RESOLVER=auto`)
- `$PERMUTATIONS_WORDLIST_MODE` - Wordlist selection (`auto`|`full`|`short`)
- `$PERMUTATIONS_SHORT_THRESHOLD` - Subdomain count threshold for short wordlist (default: 100)

## Error Codes

Defined in `lib/validation.sh`:
- `E_SUCCESS=0` - Success
- `E_GENERAL=1` - General error
- `E_MISSING_DEP=2` - Missing dependency
- `E_INVALID_INPUT=3` - Invalid user input
- `E_CONFIG=8` - Configuration error

## Testing

```bash
make test          # Unit tests only
make test-security # Security tests only
make test-all      # All tests
make lint          # Shellcheck errors
make lint-fix      # Shellcheck warnings with context
```
