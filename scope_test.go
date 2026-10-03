package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir() // already resolved, but resolve anyway for determinism
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestScopeCheckAcceptsInside(t *testing.T) {
	root := tempRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ScopeCheck(root, filepath.Join(root, "sub", "file.txt")); err != nil {
		t.Fatalf("inside root should pass: %v", err)
	}
	if err := ScopeCheck(root, "sub/file.txt"); err != nil {
		t.Fatalf("relative path should resolve against root: %v", err)
	}
	if err := ScopeCheck(root, root); err != nil {
		t.Fatalf("the root itself is inside: %v", err)
	}
}

func TestScopeCheckRejectsOutside(t *testing.T) {
	root := tempRoot(t)
	for _, p := range []string{"/etc/passwd", "/", filepath.Dir(root), root + "/../other"} {
		if err := ScopeCheck(root, p); err == nil {
			t.Errorf("path %q must be denied", p)
		} else if !strings.Contains(err.Error(), "outside workspace root") {
			t.Errorf("denial for %q is not human-readable: %v", p, err)
		}
	}
}

func TestScopeCheckRejectsSymlinkEscape(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Symlink inside the workspace pointing outside.
	link := filepath.Join(root, "innocent")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if err := ScopeCheck(root, link); err == nil {
		t.Fatal("symlink to outside must be denied")
	}
	// Symlinked *directory* inside the workspace pointing outside.
	dirLink := filepath.Join(root, "docs")
	if err := os.Symlink(outside, dirLink); err != nil {
		t.Fatal(err)
	}
	if err := ScopeCheck(root, filepath.Join(dirLink, "secret.txt")); err == nil {
		t.Fatal("path through a symlinked directory escape must be denied")
	}
}

func TestScopeCheckRejectsSymlinkedParentOfNewFile(t *testing.T) {
	// fs.write to a not-yet-existing file whose parent is a symlink that
	// escapes the workspace. The file does not exist, so the check must
	// resolve the deepest existing ancestor (the symlinked parent).
	root := tempRoot(t)
	outside := tempRoot(t)
	dirLink := filepath.Join(root, "escape")
	if err := os.Symlink(outside, dirLink); err != nil {
		t.Fatal(err)
	}
	if err := ScopeCheck(root, filepath.Join(dirLink, "newfile.txt")); err == nil {
		t.Fatal("writing through a symlinked parent escape must be denied")
	}
}

func TestScopeCheckAllowsNewFileInside(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "does", "not", "exist", "yet.txt")
	if err := ScopeCheck(root, p); err != nil {
		t.Fatalf("new file inside root should pass: %v", err)
	}
}

func TestScopeCheckDotDotEscape(t *testing.T) {
	root := tempRoot(t)
	// ".."-heavy relative path.
	if err := ScopeCheck(root, filepath.Join("..", "..", "etc", "passwd")); err == nil {
		t.Fatal("relative .. escape must be denied")
	}
}

func TestScopeCheckAcceptsRootSymlinkForm(t *testing.T) {
	// root given as /tmp/x while the OS resolves /tmp -> /private/tmp:
	// both sides resolve, so a legitimate call must pass.
	root := tempRoot(t)
	alt := root
	if strings.HasPrefix(root, "/private/") {
		alt = "/tmp" + strings.TrimPrefix(root, "/private")
	}
	if err := ScopeCheck(alt, filepath.Join(alt, "f.txt")); err != nil {
		t.Fatalf("symlinked root spelling should still pass: %v", err)
	}
}

func TestScopeCheckEmptyAndNul(t *testing.T) {
	root := tempRoot(t)
	if err := ScopeCheck(root, ""); err == nil {
		t.Error("empty path must be denied")
	}
	if err := ScopeCheck(root, "a\x00b"); err == nil {
		t.Error("NUL byte must be denied")
	}
}

func TestScopeCheckAllRoots(t *testing.T) {
	a := tempRoot(t)
	b := tempRoot(t)
	if err := ScopeCheckAll([]string{a, b}, filepath.Join(b, "x.txt")); err != nil {
		t.Fatalf("path in second root should pass: %v", err)
	}
	if err := ScopeCheckAll([]string{a}, "/etc/passwd"); err == nil {
		t.Fatal("escape from all roots must be denied")
	}
	if err := ScopeCheckAll(nil, "/etc/passwd"); err == nil {
		t.Fatal("no configured roots must deny everything")
	}
}
