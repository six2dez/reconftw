# Mock Tools for Testing

This directory contains mock implementations of external tools used by reconFTW.
These mocks allow testing without making actual network calls.

## Usage

Add this directory to PATH before running tests:

```bash
export PATH="$(pwd)/tests/mocks:$PATH"
```

## Available Mocks

- `subfinder` - Returns predefined subdomain list
- `httpx` - Returns predefined HTTP probe results
- `nuclei` - Returns empty results (no vulns)

## Creating New Mocks

1. Create an executable script with the tool name
2. Parse arguments to determine expected output
3. Return realistic-looking output
4. Exit with appropriate status code
