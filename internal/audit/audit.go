// Package audit computes SHA-256 fingerprints, so a report says exactly which
// evidence and which policies produced the result.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"slices"
)

// hex SHA-256 of a file's bytes
func File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// hex SHA-256 over all policy modules (file name -> source).
// names are sorted and each part ends with a 0 byte, so the hash is the same on
// every run and "a"+"bc" cannot collide with "ab"+"c"
func Policies(modules map[string]string) string {
	h := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		h.Write([]byte(name)) // hash.Hash.Write never returns an error
		h.Write([]byte{0})
		h.Write([]byte(modules[name]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// short form for humans: "9a1f…c3"
func Short(hash string) string {
	if len(hash) <= 6 {
		return hash
	}
	return hash[:4] + "…" + hash[len(hash)-2:]
}
