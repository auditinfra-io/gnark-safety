package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

const maxPatterns = 64

// errOutsideRoot marks a pattern, symlink, or replace directive that reaches
// outside the root the server was started with.
var errOutsideRoot = errors.New("outside the server root")

// resolveRoot returns the absolute, symlink-free form of dir.
func resolveRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return real, nil
}

// within reports whether path is root or below it. Both must be cleaned and
// symlink-free.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// checkPatterns accepts only package patterns relative to root ("." or
// "./dir", optionally ending in "/..."), and refuses any whose directory, or
// a symlink inside the directories they cover, or a local replace directive
// of the module they belong to, resolves outside root. Import-path patterns
// are refused: they would load code from the module cache or GOPATH rather
// than from the directory the user pointed the server at.
func checkPatterns(ctx context.Context, root string, patterns []string) error {
	if len(patterns) == 0 {
		return errors.New("at least one package pattern, such as ./..., is required")
	}
	if len(patterns) > maxPatterns {
		return fmt.Errorf("at most %d package patterns are accepted", maxPatterns)
	}
	checkedModules := map[string]bool{}
	for _, pattern := range patterns {
		base, recursive, err := splitPattern(pattern)
		if err != nil {
			return err
		}
		dir, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(base)))
		if err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
		if !within(root, dir) {
			return fmt.Errorf("pattern %q resolves to %s, %w", pattern, dir, errOutsideRoot)
		}
		if err := checkSymlinks(ctx, root, dir, recursive); err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
		if gomod := findGoMod(dir); gomod != "" && !checkedModules[gomod] {
			checkedModules[gomod] = true
			if err := checkReplaces(root, gomod); err != nil {
				return err
			}
		}
	}
	return nil
}

func splitPattern(pattern string) (base string, recursive bool, err error) {
	if pattern != "." && pattern != "./..." && !strings.HasPrefix(pattern, "./") {
		return "", false, fmt.Errorf("pattern %q must start with ./ and stay below the server root, as ./... or ./circuits do", pattern)
	}
	base = pattern
	if base == "./..." {
		base, recursive = ".", true
	} else if strings.HasSuffix(base, "/...") {
		base, recursive = strings.TrimSuffix(base, "/..."), true
	}
	if strings.Contains(base, "...") || strings.ContainsAny(base, "\\\x00") {
		return "", false, fmt.Errorf("pattern %q: the only wildcard accepted is a trailing /... suffix", pattern)
	}
	for _, element := range strings.Split(base, "/") {
		if element == ".." {
			return "", false, fmt.Errorf("pattern %q: .. is not accepted", pattern)
		}
	}
	return base, recursive, nil
}

// checkSymlinks refuses a symlink in dir (and, when recursive, below it)
// whose target is outside root. Directories the go command never descends
// into for ./... (names starting with . or _, and testdata) are skipped.
func checkSymlinks(ctx context.Context, root, dir string, recursive bool) error {
	check := func(path string) error {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil // a dangling link cannot be read
		}
		if !within(root, target) {
			rel, _ := filepath.Rel(root, path)
			return fmt.Errorf("symlink %s points to %s, %w", filepath.ToSlash(rel), target, errOutsideRoot)
		}
		return nil
	}
	if !recursive {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Type()&fs.ModeSymlink != 0 {
				if err := check(filepath.Join(dir, entry.Name())); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() && path != dir && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata") {
			return filepath.SkipDir
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return check(path)
		}
		return nil
	})
}

// findGoMod returns the go.mod governing dir, or "".
func findGoMod(dir string) string {
	for {
		candidate := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// checkReplaces refuses a module whose local replace directives point
// outside root: the go command would load that code as part of the scan.
func checkReplaces(root, gomod string) error {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return err
	}
	file, err := modfile.Parse(gomod, data, nil)
	if err != nil {
		return fmt.Errorf("parse %s: %w", gomod, err)
	}
	for _, replace := range file.Replace {
		if replace.New.Version != "" {
			continue // a module version, fetched and verified like any other
		}
		target := replace.New.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(gomod), target)
		}
		if real, err := filepath.EvalSymlinks(target); err == nil {
			target = real
		}
		if !within(root, filepath.Clean(target)) {
			return fmt.Errorf("%s replaces %s with %s, %w", gomod, replace.Old.Path, replace.New.Path, errOutsideRoot)
		}
	}
	return nil
}
