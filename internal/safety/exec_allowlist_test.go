package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestExecUsageAllowlist(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine current file path")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	seen := map[string]map[string]bool{}
	fileSet := token.NewFileSet()

	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		relPath, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || ident.Name != "exec" {
				return true
			}

			method := selector.Sel.Name
			if method != "Command" && method != "CommandContext" && method != "LookPath" {
				return true
			}

			allowedMethods, ok := AllowedExecUses[relPath]
			if !ok || !allowedMethods[method] {
				t.Errorf("unauthorized os/exec usage: %s uses exec.%s", relPath, method)
				return true
			}

			if seen[relPath] == nil {
				seen[relPath] = map[string]bool{}
			}
			seen[relPath][method] = true
			return true
		})

		return nil
	})
	if err != nil {
		t.Fatalf("failed to scan repository: %v", err)
	}

	var staleEntries []string
	for filePath, methods := range AllowedExecUses {
		for method := range methods {
			if !seen[filePath][method] {
				staleEntries = append(staleEntries, filePath+":"+method)
			}
		}
	}
	if len(staleEntries) > 0 {
		sort.Strings(staleEntries)
		t.Fatalf("stale exec allowlist entries: %s", strings.Join(staleEntries, ", "))
	}
}
