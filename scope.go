package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScopeCheck verifies that path is inside the workspace root *after symlink
// resolution to the final target*. This is the only correct way to scope a
// path: a symlink inside the workspace that points at /etc is an escape, and
// it must be caught by resolving, not by string-prefixed matching.
//
// Rules:
//
//   - path may be absolute, or relative (interpreted against root).
//   - The path itself does not need to exist (fs.write creates files), so
//     the deepest existing ancestor is resolved and the non-existent tail is
//     carried through verbatim (after Clean).
//   - The root is resolved too: on macOS /tmp is a symlink to /private/tmp,
//     and a root/path pair that disagrees would deny legitimate calls.
//   - Anything that resolves to the root itself or beneath it passes.
//     Anything else — including symlinked escapes, ".." chains, and
//     path-traversal tricks — is an escape attempt and returns an error.
//   - NUL bytes are rejected outright.
//
// The error is returned for the denial audit record; its text is
// human-readable by contract.
func ScopeCheck(root, path string) error {
	_, err := ScopeResolve(root, path)
	return err
}

// ScopeResolve is ScopeCheck that also returns the resolved absolute target:
// where the path actually lands after symlink resolution. The pipeline uses
// this to hand handlers fully-resolved absolute paths.
func ScopeResolve(root, path string) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if path == "" {
		return "", errors.New("path is empty")
	}

	rootResolved, err := resolveExisting(root)
	if err != nil {
		return "", fmt.Errorf("workspace root %q is not usable: %w", root, err)
	}
	if !filepath.IsAbs(rootResolved) {
		return "", fmt.Errorf("workspace root %q is not absolute", root)
	}

	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, abs)
	}
	abs = filepath.Clean(abs)

	target, err := resolveExisting(abs)
	if err != nil {
		return "", fmt.Errorf("path %q could not be resolved: %w", path, err)
	}

	if !contained(target, rootResolved) {
		return "", fmt.Errorf(
			"path %q resolves to %q which is outside workspace root %q — refusing (workspace escape attempt)",
			path, target, rootResolved)
	}
	return target, nil
}

// ResolveInRoots resolves a path against the allowed roots (same semantics
// as ScopeCheckAll) and returns the resolved absolute target inside the
// matching root. Used by the pipeline to absolutize path arguments before
// handlers run, so a handler never sees a relative path whose meaning
// depends on the agent's own working directory.
func ResolveInRoots(roots []string, path string) (string, error) {
	if len(roots) == 0 {
		return "", fmt.Errorf("no workspace roots are configured; refusing path %q", path)
	}
	var firstErr error
	for _, root := range roots {
		resolved, err := ScopeResolve(root, path)
		if err == nil {
			return resolved, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", firstErr
}

// ScopeCheckAll is ScopeCheck against a list of allowed roots; the path must
// be inside at least one of them.
func ScopeCheckAll(roots []string, path string) error {
	if len(roots) == 0 {
		return fmt.Errorf("no workspace roots are configured; refusing path %q", path)
	}
	var firstErr error
	for _, root := range roots {
		err := ScopeCheck(root, path)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// contained reports whether target is root or strictly beneath it.
func contained(target, root string) bool {
	if target == root {
		return true
	}
	return strings.HasPrefix(target, root+string(os.PathSeparator))
}

// resolveExisting resolves symlinks along a path. If the path (or part of it)
// does not exist, the deepest existing ancestor is resolved with
// EvalSymlinks and the remainder is appended. This keeps fs.write usable for
// new files while still catching a symlinked *parent* directory escape.
func resolveExisting(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if !filepath.IsAbs(p) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		p = abs
	}
	p = filepath.Clean(p)

	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return resolved, nil
	}

	// Walk up to the deepest existing ancestor.
	dir := filepath.Dir(p)
	for dir != p {
		resolved, err = filepath.EvalSymlinks(dir)
		if err == nil {
			tail := strings.TrimPrefix(p, dir)
			tail = strings.TrimPrefix(tail, string(os.PathSeparator))
			out := filepath.Join(resolved, tail)
			return filepath.Clean(out), nil
		}
		p = dir
		dir = filepath.Dir(p)
	}
	return "", fmt.Errorf("no existing ancestor to resolve: %w", err)
}
