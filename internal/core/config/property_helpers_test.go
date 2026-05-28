// Test-only file helpers (split so property_test.go stays small).
package config_test

import "os"

func writeFileImpl(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
