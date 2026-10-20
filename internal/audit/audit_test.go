package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFile — checks the SHA-256 of a file against a known value.
// TestFileMissingIsAnError — checks that a missing file returns an error.
// TestPoliciesIsStable — checks that the policy hash ignores map order and changes with names or content.
// TestShort — checks the short "9a1f…c3" form.

func TestFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := File(path)
	if err != nil {
		t.Fatal(err)
	}
	// echo -n hello | shasum -a 256
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestFileMissingIsAnError(t *testing.T) {
	if _, err := File(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error")
	}
}

func TestPoliciesIsStable(t *testing.T) {
	a := Policies(map[string]string{"a.rego": "x", "b.rego": "y"})
	b := Policies(map[string]string{"b.rego": "y", "a.rego": "x"})
	if a != b {
		t.Error("hash depends on map order")
	}
	if a == Policies(map[string]string{"a.rego": "x", "b.rego": "z"}) {
		t.Error("hash ignores content")
	}
	if Policies(map[string]string{"a": "bc"}) == Policies(map[string]string{"ab": "c"}) {
		t.Error("name and content boundaries collide")
	}
}

func TestShort(t *testing.T) {
	if got := Short("9a1f0000000000c3"); got != "9a1f…c3" {
		t.Errorf("got %q", got)
	}
	if got := Short("abc"); got != "abc" {
		t.Errorf("got %q", got)
	}
}
