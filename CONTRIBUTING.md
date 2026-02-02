# Contributing to reconFTW

Thank you for your interest in contributing to reconFTW! This guide covers everything you need to get started.

## Code of Conduct

Please read and follow the [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions.

## Security Vulnerabilities

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Development Setup

1. **Fork and clone** the repository:

   ```bash
   git clone https://github.com/<your-username>/reconftw
   cd reconftw
   git remote add upstream https://github.com/six2dez/reconftw
   git checkout dev
   ```

2. **Install dependencies**:

   ```bash
   ./install.sh
   ```

3. **Install dev tools** (optional but recommended):

   ```bash
   # Linting
   brew install shellcheck    # or: apt install shellcheck
   # Formatting
   brew install shfmt         # or: go install mvdan.cc/sh/v3/cmd/shfmt@latest
   # Testing
   brew install bats-core     # or: apt install bats
   ```

## Project Structure

```
reconftw/
├── reconftw.sh              # Entry point (~536 lines) — arg parsing, module loading, dispatch
├── reconftw.cfg             # Default configuration file
├── install.sh               # Installer script
├── Makefile                 # Data management, lint, fmt, test targets
├── modules/
│   ├── core.sh              # Lifecycle, logging, notifications, cleanup
│   ├── modes.sh             # Scan modes, argument parsing, help
│   ├── subdomains.sh        # Subdomain enumeration functions
│   ├── web.sh               # Web analysis, fuzzing, JS checks
│   ├── vulns.sh             # Vulnerability scanning functions
│   ├── osint.sh             # OSINT module functions
│   ├── axiom.sh             # Axiom/Ax fleet management helpers
│   └── utils.sh             # Shared utilities, sanitization, validation
├── tests/
│   ├── run_tests.sh         # Test runner (--all for integration)
│   ├── unit/                # bats-core unit tests
│   ├── integration/         # bats-core integration tests
│   └── fixtures/            # Test data files
├── Docker/
│   └── Dockerfile           # Official Docker image definition
└── Terraform/               # AWS deployment via Terraform + Ansible
```

## Code Style

- **Shell**: Bash 4+ required. Use `#!/bin/bash` shebang.
- **Formatter**: `shfmt` with project defaults — `shfmt -w -i 4 -bn -ci`
- **Linter**: `shellcheck -S warning`
- Run both before submitting:

  ```bash
  make lint
  make fmt
  ```

## Input Safety Rules

All user-supplied input **must** be sanitized before use:

- Use `sanitize_domain()` for domain names
- Use `sanitize_ip()` for IP/CIDR input
- Use `sanitize_interlace_input()` for arguments passed to interlace
- **Never** use `eval` on user input
- **Always** quote variables: `"${var}"`, not `$var`

## How to Add a New Function

1. **Choose the right module**: Place your function in the appropriate file under `modules/`:
   - Subdomain work → `subdomains.sh`
   - Web analysis → `web.sh`
   - Vulnerability checks → `vulns.sh`
   - OSINT → `osint.sh`
   - Utilities → `utils.sh`

2. **Follow the lifecycle pattern**:

   ```bash
   function my_new_check() {
       start_func "${FUNCNAME[0]}" "Running my new check"
       # ... your logic ...
       end_func "Results: ${FUNCNAME[0]}" "${FUNCNAME[0]}"
   }
   ```

3. **Add a config toggle** in `reconftw.cfg`:

   ```bash
   MY_NEW_CHECK=true  # Enable or disable my new check
   ```

4. **Write tests**: Add a bats test in `tests/unit/`:

   ```bash
   @test "my_new_check validates input" {
       source ./reconftw.sh --source-only
       run my_new_check "valid-input"
       [ "$status" -eq 0 ]
   }
   ```

5. **Call it from a mode**: Wire the function into the appropriate mode in `modules/modes.sh`.

## How to Add a New Tool Integration

1. Add the install logic to `install.sh`
2. Add configuration variables to `reconftw.cfg`
3. Add the function that calls the tool to the appropriate module
4. Wire it into the relevant scan mode in `modes.sh`
5. Add a `--check-tools` entry if the tool is required
6. Write tests covering basic invocation
7. Update the Features section in `README.md`

## Configuration Change Guidelines

When adding new configuration variables:

- Use the environment-variable fallback pattern for secrets:

  ```bash
  MY_API_KEY="${MY_API_KEY:-}"
  ```

- Use descriptive names with comments explaining the purpose
- Group related variables together in `reconftw.cfg`
- Document new variables in the README configuration section

## Testing

### Running Tests

```bash
# Unit tests only
make test

# Unit + integration tests
make test-all

# Via the runner script
./tests/run_tests.sh         # unit only
./tests/run_tests.sh --all   # unit + integration
```

### Writing Tests

Tests use [bats-core](https://github.com/bats-core/bats-core). Place unit tests in `tests/unit/` with the `.bats` extension.

Use the `--source-only` pattern to load functions without executing the main script:

```bash
#!/usr/bin/env bats

setup() {
    source ./reconftw.sh --source-only
}

@test "sanitize_domain strips invalid chars" {
    result="$(sanitize_domain 'exam;ple.com')"
    [ "$result" = "example.com" ]
}
```

### CI Pipeline

The GitHub Actions workflow (`.github/workflows/tests.yml`) runs on every push and pull request:

1. **ShellCheck** — lints `reconftw.sh`, `modules/*.sh`, and `install.sh`
2. **Unit Tests** — runs `bats tests/unit/*.bats`
3. **Integration Tests** — installs reconFTW and runs tool checks

## Pull Request Process

1. **Target the `dev` branch** — never submit PRs directly to `main`
2. **Keep PRs focused** — one feature or fix per PR
3. **Include tests** for new functionality
4. **Pass linting**: `make lint` must pass
5. **Describe your changes** clearly in the PR description
6. **Reference issues** if applicable (e.g., "Fixes #123")

## Bug Reports

Submit bugs via [GitHub Issues](https://github.com/six2dez/reconftw/issues/new/choose). Include:

- reconFTW version (`git describe --tags`)
- OS and Bash version (`bash --version`)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output

## Feature Requests

Open a [GitHub Issue](https://github.com/six2dez/reconftw/issues/new/choose) with:

- A clear description of the feature
- Use case / motivation
- Example configuration or usage if applicable
