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
