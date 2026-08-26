// usable.go — the single definition of "this file holds DNS resolvers".
//
// There used to be two answers to that question in this repo, and they
// disagreed. `fileUsable` here tested SIZE, so a 12-byte remnant of a failed
// download, or an HTML error page from a mirror that answered 200, counted as a
// working resolver list and every DNS operation downstream ran on it.
// `resolverListUsable` in internal/modules/subdomains counted NON-EMPTY LINES,
// which rejects a whitespace-only file but still accepts that HTML page — a
// `<html>` line is non-empty.
//
// Both now route here, so the two cannot drift apart again: a resolver list is
// usable when it holds at least one line that could actually be handed to
// puredns or massdns as a nameserver.

package resolvers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// maxResolverScanBytes bounds the read. A resolver list is a few tens of KB;
// anything larger is either not a resolver list or has enough shaped lines in
// its first megabyte to answer the question.
const maxResolverScanBytes = 1 << 20

// ResolverShapedLine reports whether one line of a resolver file names a
// nameserver. Blank lines and `#` / `;` comments are skipped (real published
// lists carry both), and an optional `:port` suffix is tolerated because massdns
// accepts one.
func ResolverShapedLine(line string) bool {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
		return false
	}
	// Strip an inline comment, e.g. "1.1.1.1  # cloudflare".
	if i := strings.IndexAny(s, "#;"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	// "1.1.1.1:53" or "[2606:4700:4700::1111]:53"
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host) != nil
	}
	return false
}

// CountResolverLines returns the number of resolver-shaped lines in path.
//
// It is the canonical count for the whole tool: internal/modules/subdomains
// delegates its own resolver gates to this function so a list the boot-time
// acquisition calls usable cannot be a list the brute-force gate calls empty.
func CountResolverLines(path string) (int, error) {
	if path == "" {
		return 0, fmt.Errorf("resolver file path is empty")
	}
	f, err := os.Open(path) //nolint:gosec // path comes from cfg.Paths.Resolvers (nopath_traversal validated at config load)
	if err != nil {
		return 0, fmt.Errorf("open resolver file %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only count

	count := 0
	read := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		read += len(line) + 1
		if ResolverShapedLine(line) {
			count++
		}
		if read >= maxResolverScanBytes {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return count, err
	}
	return count, nil
}
