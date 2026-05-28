// Source: ADR §3.4 line 1319 — input_hash formula.
//
// input_hash = SHA-256( task_name || \0 || target || \0 || cfg_slice_json || \0 || wordlists_lock )
//
// Null-byte separators prevent prefix-collision attacks (e.g. task="ab"
// target="" vs task="a" target="b" would otherwise concat identically).
//
// Including task_name + target in the hash bytes is belt-and-suspenders
// over the PRIMARY KEY (task_name, target, input_hash) constraint —
// when a Scheduler queries by hash alone (debugging, audit), the hash
// identifies exactly one task uniquely.
package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
)

// InputHash computes the SHA-256 hash that identifies the task's full
// input set. Changing ANY of (taskName, target, cfgSliceJSON,
// wordlistsLockContent) invalidates the checkpoint and forces re-run on
// next startup.
func InputHash(taskName string, target string, cfgSliceJSON []byte, wordlistsLockContent []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(taskName))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(cfgSliceJSON)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(wordlistsLockContent)
	return hex.EncodeToString(h.Sum(nil))
}
