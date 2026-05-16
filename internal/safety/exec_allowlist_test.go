package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
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

		execImportNames, dotImportedExec := osExecImportNames(file)
		if dotImportedExec {
			t.Errorf("unauthorized os/exec usage: %s uses dot import for os/exec", relPath)
		}

		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || !execImportNames[ident.Name] {
				return true
			}

			method := selector.Sel.Name
			allowedMethods, ok := AllowedExecUses[relPath]
			if !ok || !allowedMethods[method] {
				t.Errorf("unauthorized os/exec usage: %s uses os/exec.%s", relPath, method)
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

func osExecImportNames(file *ast.File) (map[string]bool, bool) {
	names := make(map[string]bool)
	dotImported := false

	for _, spec := range file.Imports {
		importPath := strings.Trim(spec.Path.Value, "\"")
		if importPath != "os/exec" {
			continue
		}

		switch {
		case spec.Name == nil:
			names[path.Base(importPath)] = true
		case spec.Name.Name == ".":
			dotImported = true
		default:
			names[spec.Name.Name] = true
		}
	}

	return names, dotImported
}

func TestOSExecImportNames(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantNames   []string
		wantDotExec bool
	}{
		{
			name: "default import name",
			source: `package sample
import "os/exec"
`,
			wantNames: []string{"exec"},
		},
		{
			name: "alias import name",
			source: `package sample
import osexec "os/exec"
`,
			wantNames: []string{"osexec"},
		},
		{
			name: "dot import",
			source: `package sample
import . "os/exec"
`,
			wantDotExec: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "sample.go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile() error = %v", err)
			}

			names, dotExec := osExecImportNames(file)
			if dotExec != tt.wantDotExec {
				t.Fatalf("dot import = %v, want %v", dotExec, tt.wantDotExec)
			}

			for _, name := range tt.wantNames {
				if !names[name] {
					t.Fatalf("expected import name %q to be detected in %v", name, names)
				}
			}
		})
	}
}
