package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ArgvRule is the shape rule for one allowlisted binary.
type ArgvRule struct {
	// MaxArgs is the maximum number of arguments *after* the binary.
	MaxArgs int
	// Subcommands, when non-empty, requires argv[1] to be one of them.
	Subcommands []string
	// ForbiddenFlags denies any argument exactly equal to one of these.
	ForbiddenFlags []string
	// CwdRequired marks binaries that must be run inside a scoped cwd
	// (pytest, make). Enforced by the caller against workspace roots.
	CwdRequired bool
	// Denied marks binaries that are explicitly refused even though a
	// naive "starts with a known name" check might accept them. The
	// allowlist is closed, so this is belt-and-braces for shells.
	Denied bool
}

// DefaultArgvRules is the closed allowlist for shell.run / shell.test.
//
// Three properties, from docs/05:
//
//  1. The binary must be a known allowlist entry (no first-arg patterns).
//  2. Subcommands are allowlisted rather than pattern-matched.
//  3. `python3 -c` is denied outright because -c re-opens arbitrary
//     evaluation — a shell in disguise. The same reasoning bans shells
//     entirely: sh/bash/zsh/dash/fish are Denied.
//
// Anything not listed here is denied; the allowlist is closed.
func DefaultArgvRules() map[string]ArgvRule {
	return map[string]ArgvRule{
		"git":    {MaxArgs: 12, Subcommands: []string{"status", "log", "diff", "add", "commit", "push", "branch", "checkout", "stash"}},
		"pytest": {MaxArgs: 20, CwdRequired: true},
		"python3": {
			MaxArgs:        10,
			ForbiddenFlags: []string{"-c"}, // -c is a shell in disguise
		},
		"uv":     {MaxArgs: 20, Subcommands: []string{"run", "sync", "pytest", "pip"}},
		"npm":    {MaxArgs: 20, Subcommands: []string{"test", "run", "ci", "install"}},
		"make":   {MaxArgs: 8, CwdRequired: true},
		"go":     {MaxArgs: 12, Subcommands: []string{"build", "test", "vet", "fmt"}},
		"grep":   {MaxArgs: 12},
		"rg":     {MaxArgs: 12},
		"ls":     {MaxArgs: 8},
		"cat":    {MaxArgs: 12},

		// Shells are denied entirely. No exception, ever.
		"sh":   {Denied: true},
		"bash": {Denied: true},
		"zsh":  {Denied: true},
		"dash": {Denied: true},
		"fish": {Denied: true},
	}
}

// ArgvPolicy validates argv arrays for shell capabilities.
type ArgvPolicy struct {
	rules map[string]ArgvRule
}

// NewArgvPolicy builds a policy from the given rules. Use DefaultArgvRules
// unless you have a reviewed reason not to.
func NewArgvPolicy(rules map[string]ArgvRule) *ArgvPolicy {
	return &ArgvPolicy{rules: rules}
}

// DefaultArgvPolicy returns the standard closed allowlist.
func DefaultArgvPolicy() *ArgvPolicy { return NewArgvPolicy(DefaultArgvRules()) }

// Restrict narrows the policy to the named binaries (AH_ALLOWED_BINARIES).
// Widening is impossible by construction: only names already in the policy
// are kept, so this can only make the allowlist smaller. Returns an error if
// a name is unknown, so a typo in config fails loudly instead of silently
// narrowing.
func (p *ArgvPolicy) Restrict(names []string) (*ArgvPolicy, error) {
	if len(names) == 0 {
		return p, nil
	}
	rules := make(map[string]ArgvRule, len(names))
	for _, n := range names {
		rule, ok := p.rules[n]
		if !ok {
			return nil, fmt.Errorf("binary %q is not in the device argv allowlist; refusing to configure it", n)
		}
		rules[n] = rule
	}
	return NewArgvPolicy(rules), nil
}

// RuleFor returns the rule for a binary name (the base of argv[0]).
func (p *ArgvPolicy) RuleFor(bin string) (ArgvRule, bool) {
	r, ok := p.rules[bin]
	return r, ok
}

// Check validates the *shape* of an argv array. It does not touch the
// filesystem: binary path resolution and the world-writable-directory check
// live in ResolveBinary/VerifyBinaryPath, which callers run alongside Check.
func (p *ArgvPolicy) Check(argv []string) error {
	if len(argv) == 0 {
		return errors.New("argv is empty")
	}
	bin := filepath.Base(argv[0])
	if bin == "." || bin == ".." || bin == "/" || bin == "" {
		return fmt.Errorf("argv[0] %q does not name a binary", argv[0])
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("argument contains a NUL byte")
		}
	}

	rule, ok := p.rules[bin]
	if !ok {
		return fmt.Errorf("binary %q is not on the argv allowlist; only %s are permitted",
			bin, p.names())
	}
	if rule.Denied {
		return fmt.Errorf("binary %q is a shell and is denied outright; the harness never spawns a shell", bin)
	}
	if rule.Subcommands != nil && len(argv) == 1 {
		return fmt.Errorf("%s requires a subcommand (one of: %s)", bin, strings.Join(rule.Subcommands, ", "))
	}
	if rule.Subcommands != nil {
		sub := argv[1]
		allowed := false
		for _, s := range rule.Subcommands {
			if sub == s {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%s subcommand %q is not allowed (one of: %s)", bin, sub, strings.Join(rule.Subcommands, ", "))
		}
	}
	if n := len(argv) - 1; n > rule.MaxArgs {
		return fmt.Errorf("%s takes at most %d arguments, got %d", bin, rule.MaxArgs, n)
	}
	for _, forbidden := range rule.ForbiddenFlags {
		for _, a := range argv {
			if a == forbidden {
				return fmt.Errorf("%s %s is denied: the flag re-opens arbitrary code evaluation (a shell in disguise)", bin, forbidden)
			}
		}
	}
	return nil
}

func (p *ArgvPolicy) names() string {
	out := make([]string, 0, len(p.rules))
	for n := range p.rules {
		if !p.rules[n].Denied {
			out = append(out, n)
		}
	}
	// deterministic order for a stable denial message
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return strings.Join(out, ", ")
}

// ResolveBinary turns argv[0] into an absolute path. A bare name is resolved
// through envPath (the caller passes PATH); a path containing "/" must be
// absolute — a relative binary path is refused, because "run the tool that
// happens to be in the current directory" is exactly how a compromised
// workspace gets its code executed.
func ResolveBinary(argv0, envPath string) (string, error) {
	if argv0 == "" {
		return "", errors.New("argv[0] is empty")
	}
	if strings.ContainsRune(argv0, 0) {
		return "", errors.New("argv[0] contains a NUL byte")
	}
	if strings.Contains(argv0, "/") {
		if !filepath.IsAbs(argv0) {
			return "", fmt.Errorf("binary path %q is relative; the binary must be an absolute path or a bare name found on PATH", argv0)
		}
		return filepath.Clean(argv0), nil
	}
	for _, dir := range filepath.SplitList(envPath) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, argv0)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue // not executable
		}
		return candidate, nil
	}
	return "", fmt.Errorf("binary %q was not found on PATH", argv0)
}

// VerifyBinaryPath checks that an absolute binary path (and the final target
// if it is a symlink) lives in a directory chain that is NOT writable by
// world. If any ancestor directory (or the binary itself) is world-writable,
// a compromised local process could swap the tool between the check and the
// spawn — so the spawn is refused instead.
func VerifyBinaryPath(abs string) error {
	if !filepath.IsAbs(abs) {
		return fmt.Errorf("binary path %q is not absolute", abs)
	}
	target, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("binary %q could not be resolved: %w", abs, err)
	}
	for _, p := range []string{abs, target} {
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("binary %q could not be inspected: %w", p, err)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("binary %q is writable by world; refusing to execute it", p)
		}
		if err := verifyDirChain(filepath.Dir(p)); err != nil {
			return err
		}
	}
	return nil
}

// verifyDirChain walks from dir up to "/" and fails on any world-writable
// directory.
func verifyDirChain(dir string) error {
	for {
		if worldWritable(dir) {
			return fmt.Errorf("directory %q in the binary's path is writable by world; refusing to execute a binary that could be swapped from there", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func worldWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil {
		// An unstatable directory is not one we can vouch for.
		return true
	}
	return info.Mode().Perm()&0o002 != 0
}

// ValidateBinary is the composite check the pipeline runs on shell argv:
// resolve argv[0], then verify the directory chain. Returns the absolute
// path to execute.
func ValidateBinary(argv0, envPath string) (string, error) {
	abs, err := ResolveBinary(argv0, envPath)
	if err != nil {
		return "", err
	}
	if err := VerifyBinaryPath(abs); err != nil {
		return "", err
	}
	return abs, nil
}
