package manifest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Diagnostic is a problem found without building images or contacting a host.
// Path uses the manifest's field names; line and column are one-based when known.
type Diagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

// CheckReport is the stable JSON result of an offline source check. Valid means
// the manifest and its referenced local inputs passed, not that a host is ready.
type CheckReport struct {
	SchemaVersion string       `json:"schema_version"`
	Source        string       `json:"source"`
	Manifest      string       `json:"manifest"`
	App           string       `json:"app,omitempty"`
	Valid         bool         `json:"valid"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
}

// CheckSource validates the authoritative manifest and the local paths a deploy
// needs. It never opens a state store, contacts Docker, reads secrets or runs code.
func CheckSource(dir, name string) CheckReport {
	r := CheckReport{SchemaVersion: SchemaVersion, Source: dir, Manifest: name, Diagnostics: []Diagnostic{}}
	positions := map[string]*yaml.Node{}
	add := func(code, path, message string) {
		d := Diagnostic{Code: code, Path: path, Message: message}
		for at := path; at != ""; {
			if n := positions[at]; n != nil {
				d.Line, d.Column = n.Line, n.Column
				break
			}
			end := strings.LastIndexAny(at, ".[")
			if end < 0 {
				break
			}
			at = at[:end]
		}
		r.Diagnostics = append(r.Diagnostics, d)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		add("source.unreadable", "", err.Error())
		return r
	}
	r.Source = root
	name, err = ResolveFileName(root, name)
	if err != nil {
		add("manifest.filename", "", err.Error())
		return r
	}
	r.Manifest = name
	manifestPath := filepath.Join(root, name)
	info, err := os.Lstat(manifestPath)
	if err != nil {
		add("manifest.unreadable", "", err.Error())
		return r
	}
	if !info.Mode().IsRegular() {
		add("manifest.file", "", name+" must be a plain file, not a link")
		return r
	}
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		add("manifest.unreadable", "", err.Error())
		return r
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&doc); err == nil {
		if len(doc.Content) > 0 {
			indexPositions(doc.Content[0], "", positions)
		}
		var extra yaml.Node
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			message := "the source must contain exactly one YAML document"
			if err != nil {
				message += ": " + err.Error()
			}
			add("manifest.documents", "", message)
			return r
		}
	}
	m, err := parseNamed(body, name)
	if err != nil {
		var typeErr *yaml.TypeError
		if errors.As(err, &typeErr) {
			for _, message := range typeErr.Errors {
				d := Diagnostic{Code: "manifest.parse", Message: message}
				if match := diagnosticLine.FindStringSubmatch(message); len(match) > 1 {
					d.Line, _ = strconv.Atoi(match[1])
					// A YAML type error names its source line, so find the most
					// specific key at that line, including an unknown field.
					field := ""
					if match := diagnosticField.FindStringSubmatch(message); len(match) > 1 {
						field = match[1]
					}
					for _, path := range sortedKeys(positions) {
						n := positions[path]
						if field != "" && path != field && !strings.HasSuffix(path, "."+field) {
							continue
						}
						if n.Line == d.Line && (d.Path == "" || len(path) > len(d.Path) || len(path) == len(d.Path) && n.Column < d.Column) {
							d.Path, d.Column = path, n.Column
						}
					}
				}
				r.Diagnostics = append(r.Diagnostics, d)
			}
		} else {
			for _, message := range strings.Split(err.Error(), "\n") {
				path, _, ok := strings.Cut(message, ":")
				if !ok || positions[path] == nil {
					path = ""
				}
				add("manifest.invalid", path, message)
				if path == "" {
					if match := diagnosticLine.FindStringSubmatch(message); len(match) > 1 {
						r.Diagnostics[len(r.Diagnostics)-1].Line, _ = strconv.Atoi(match[1])
					}
				}
			}
		}
		return r
	}
	r.App = m.App
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		add("source.unreadable", "", err.Error())
		return r
	}
	checkPath := func(path, local string, directory bool) (string, bool) {
		full, err := filepath.EvalSymlinks(filepath.Join(root, local))
		if err != nil {
			add("source.missing", path, fmt.Sprintf("%s: %v", local, err))
			return "", false
		}
		rel, err := filepath.Rel(resolvedRoot, full)
		if err != nil || filepath.IsAbs(local) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			add("source.outside", path, local+" leads outside the source directory")
			return "", false
		}
		info, err := os.Stat(full)
		if err != nil {
			add("source.unreadable", path, err.Error())
			return "", false
		}
		if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
			what := "a plain file"
			if directory {
				what = "a directory"
			}
			add("source.type", path, local+" must be "+what)
			return "", false
		}
		return full, true
	}
	for _, name := range m.WorkloadNames() {
		w := m.Workloads[name]
		at := "workloads." + name
		if w.Build != nil {
			context := w.Build.Context
			if context == "" {
				context = "."
			}
			if buildContext, ok := checkPath(at+".build.context", context, true); ok {
				dockerfile := w.Build.Dockerfile
				if dockerfile == "" {
					dockerfile = "Dockerfile"
				}
				if filepath.IsAbs(dockerfile) {
					add("source.outside", at+".build.dockerfile", "Dockerfile must be relative to its build context")
				} else {
					if _, ok := checkPath(at+".build.dockerfile", filepath.Join(context, dockerfile), false); ok {
						// Match the builder's rooted lookup too. A symlink may stay
						// inside the source yet escape this narrower build context.
						root, err := os.OpenRoot(buildContext)
						if err != nil {
							add("source.unreadable", at+".build.context", err.Error())
						} else {
							if _, err := root.Stat(dockerfile); err != nil {
								add("source.outside", at+".build.dockerfile", "Dockerfile must stay inside its build context: "+err.Error())
							}
							root.Close()
						}
					}
				}
			}
		}
		if w.Kind == Static {
			checkPath(at+".dir", w.Dir, true)
		}
	}
	if m.Data != nil && m.Data.Postgres != nil && m.Data.Postgres.Init != "" {
		local := m.Data.Postgres.Init
		full, err := filepath.EvalSymlinks(filepath.Join(root, local))
		if err != nil {
			add("source.missing", "data.postgres.init", err.Error())
		} else if info, err := os.Stat(full); err != nil {
			add("source.unreadable", "data.postgres.init", err.Error())
		} else {
			if checked, ok := checkPath("data.postgres.init", local, info.IsDir()); ok && info.IsDir() {
				entries, err := os.ReadDir(checked)
				if err != nil {
					add("source.unreadable", "data.postgres.init", err.Error())
				} else {
					found := false
					for _, entry := range entries {
						if entry.Type().IsRegular() && (strings.HasSuffix(entry.Name(), ".sql") || strings.HasSuffix(entry.Name(), ".sh") || strings.HasSuffix(entry.Name(), ".sql.gz")) {
							found = true
						}
					}
					if !found {
						add("source.init_empty", "data.postgres.init", local+" holds no .sql, .sql.gz or .sh files")
					}
				}
			}
		}
	}
	r.Valid = len(r.Diagnostics) == 0
	return r
}

var (
	diagnosticLine  = regexp.MustCompile(`line ([0-9]+):`)
	diagnosticField = regexp.MustCompile(`field ([^ ]+) not found`)
)

func indexPositions(n *yaml.Node, path string, positions map[string]*yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			child := key.Value
			if path != "" {
				child = path + "." + child
			}
			positions[child] = key
			indexPositions(value, child, positions)
		}
	case yaml.SequenceNode:
		for i, child := range n.Content {
			at := fmt.Sprintf("%s[%d]", path, i)
			positions[at] = child
			indexPositions(child, at, positions)
		}
	}
}
