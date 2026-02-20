# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| dev     | :white_check_mark: |
| 3.x     | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them responsibly by emailing **six2dez** directly:

- Email: [six2dez@gmail.com](mailto:six2dez@gmail.com)
- Subject: `[reconFTW Security] <brief description>`

You should receive a response within 72 hours acknowledging the report. The maintainer will work with you to understand and remediate the issue before any public disclosure.

## Secrets Management

reconFTW handles API keys and credentials in three ways (in order of precedence):

### 1. Environment Variables (recommended)

Set secrets as environment variables before running:

```bash
export SHODAN_API_KEY="your-key"
export WHOISXML_API="your-key"
export XSS_SERVER="your-server"
export COLLAB_SERVER="your-server"
./reconftw.sh -d target.com -r
```

### 2. secrets.cfg File

Create a `secrets.cfg` file in the reconFTW root directory. It is automatically sourced at startup and is listed in `.gitignore`:

```bash
# secrets.cfg — never commit this file
SHODAN_API_KEY="your-key"
WHOISXML_API="your-key"
XSS_SERVER="your-server"
COLLAB_SERVER="your-server"
slack_channel="your-channel"
slack_auth="xoxb-your-token"
```

### 3. Docker Runtime Secrets

When running via Docker, pass secrets with `-e` flags at runtime. Never bake secrets into the image:

```bash
docker run -it --rm \
  -e SHODAN_API_KEY="your-key" \
  -e COLLAB_SERVER="your-server" \
  -v "${PWD}/OutputFolder/:/reconftw/Recon/" \
  six2dez/reconftw:main -d example.com -r
```

## Files to Never Commit

The following files may contain secrets and must **never** be committed to version control:

| File | Purpose |
|------|---------|
| `secrets.cfg` | Local secrets override file |
| `.env` | Environment variable definitions |
| `reconftw.cfg` (with keys) | Configuration with API keys filled in |
| `*.tokens` | GitHub/GitLab token files |

Verify these are covered by `.gitignore` before pushing.

## Input Sanitization

reconFTW sanitizes all user-supplied input to prevent command injection:

| Function | Purpose |
|----------|---------|
| `sanitize_domain()` | Strips characters not valid in domain names, converts to lowercase |
| `sanitize_ip()` | Validates and cleans IP/CIDR input |
| `sanitize_interlace_input()` | Removes shell metacharacters from interlace arguments |
| `validate_domain()` | Validates domain format without modification |
| `validate_ipv4()` | Validates IPv4 address format |

All `eval` usage on user input has been removed. Variables are quoted throughout the codebase to prevent word-splitting and globbing attacks.

## Security Testing

The test suite includes security-focused tests in `tests/security/`:

- Command injection attempts via domain parameter
- Pipe and redirect injection tests
- Backtick and dollar substitution tests
- Path traversal prevention tests

Run security tests with:

```bash
make test-security
```

## Security-Related Configuration

These variables in `reconftw.cfg` control security and operational safety:

| Variable | Default | Description |
|----------|---------|-------------|
| `MIN_DISK_SPACE_GB` | `0` | Minimum disk space (GB) required before scanning starts (0 = disabled) |
| `MAX_LOG_FILES` | `10` | Maximum log files kept per target (prevents disk exhaustion) |
| `MAX_LOG_AGE_DAYS` | `30` | Auto-delete logs older than this many days |
| `STRUCTURED_LOGGING` | `false` | Enable JSON structured logging for audit trails |
| `SHOW_COMMANDS` | `false` | Log every executed command (may include sensitive data) |
| `INTRUSIVE` | `false` | Enable intrusive cloud write/CORS tests (dangerous, keep disabled) |
| `CACHE_MAX_AGE_DAYS` | `30` | Maximum cache age for wordlists/resolvers |

## Docker Security

The Dockerfile follows these security practices:

- Secrets are passed at runtime via environment variables, not embedded at build time
- A `HEALTHCHECK` directive ensures the container is monitored
- Non-essential build dependencies are removed in the final image
- The `--build-arg INSTALL_AXIOM=false` flag skips Axiom tooling when not needed
