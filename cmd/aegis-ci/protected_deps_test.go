package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/foureyes"
)

// goListPkg — нужные поля вывода `go list -json`.
type goListPkg struct {
	ImportPath string
	Dir        string
	Module     *struct {
		Path string
		Main bool
	}
	GoFiles, CgoFiles, IgnoredGoFiles, IgnoredOtherFiles, CFiles, CXXFiles, MFiles, HFiles,
	FFiles, SFiles, SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles []string
}

var buildExts = map[string]bool{
	".go": true, ".s": true, ".S": true, ".sx": true, ".c": true, ".cc": true, ".cpp": true, ".cxx": true,
	".h": true, ".hh": true, ".hpp": true, ".hxx": true, ".m": true, ".f": true, ".F": true, ".for": true,
	".f90": true, ".swig": true, ".swigcxx": true, ".syso": true,
}

// unprotectedBuildFiles возвращает файлы пакетов главного модуля, участвующие в сборке, но не защищённые правилами.
// Помимо списков go list проверяется листинг каталога: он ловит файлы мимо категорий go list.
func unprotectedBuildFiles(r foureyes.Rules, root string, pkgs []goListPkg) ([]string, error) {
	seen := map[string]bool{}
	check := func(dir, f string) error {
		rel, err := filepath.Rel(root, filepath.Join(dir, f))
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".." || strings.HasPrefix(rel, "../") {
			return fmt.Errorf("файл %s вне корня %s", rel, root)
		}
		if _, ok := r.Match(rel); !ok {
			seen[rel] = true
		}
		return nil
	}
	for _, p := range pkgs {
		if p.Module == nil || !p.Module.Main {
			continue
		}
		var lists [][]string
		for _, l := range [][]string{p.GoFiles, p.CgoFiles, p.IgnoredGoFiles, p.IgnoredOtherFiles, p.CFiles, p.CXXFiles, p.MFiles,
			p.HFiles, p.FFiles, p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles} {
			lists = append(lists, l)
		}
		for i, l := range lists {
			for _, f := range l {
				if i == 2 && strings.HasSuffix(f, "_test.go") {
					continue
				}
				if err := check(p.Dir, f); err != nil {
					return nil, err
				}
			}
		}
		ents, err := os.ReadDir(p.Dir)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			n := e.Name()
			if !e.Type().IsRegular() || !buildExts[filepath.Ext(n)] || strings.HasSuffix(n, "_test.go") {
				continue
			}
			if err := check(p.Dir, n); err != nil {
				return nil, err
			}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// Каждый файл, участвующий в сборке бинарей (Go- и не-Go-исходники, .syso, embed), защищён правилом four-eyes.json:
// иначе правка попала бы в релиз мимо цепочки bundle.
func TestBuildDepsProtected(t *testing.T) {
	const root = "../.."
	bins, _ := filepath.Glob(root + "/cmd/aegis-*")
	if len(bins) < 6 {
		t.Fatalf("cmd/aegis-*: найдено %d, ожидалось не меньше 6", len(bins))
	}
	args := []string{"list", "-deps", "-json"}
	for _, b := range bins {
		args = append(args, "./cmd/"+filepath.Base(b))
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=-mod=readonly", "GOWORK=off", "GOTOOLCHAIN=local")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v: %s", err, stderr.String())
	}
	var pkgs []goListPkg
	for dec := json.NewDecoder(bytes.NewReader(out)); ; {
		var p goListPkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	raw, err := os.ReadFile(root + "/.github/four-eyes.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := foureyes.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Защита от пустого прогона.
	mod := 0
	have := map[string]bool{}
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Main {
			mod++
			have[strings.TrimPrefix(p.ImportPath, p.Module.Path+"/")] = true
		}
	}
	for _, need := range []string{"internal/promtext", "eval/golden-synthetic", "internal/pep"} {
		if !have[need] {
			t.Errorf("пакет %s не найден среди зависимостей бинарей", need)
		}
	}
	if mod < 30 {
		t.Fatalf("пакетов модуля %d, ожидалось не меньше 30", mod)
	}
	bad, err := unprotectedBuildFiles(rules, mustAbs(t, root), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range bad {
		t.Errorf("файл сборки %s не защищён four-eyes.json: добавьте правило (и строку CODEOWNERS) в том же PR", f)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestUnprotectedBuildFiles(t *testing.T) {
	rules, err := foureyes.Load([]byte(`{"schema":"` + foureyes.Schema + `","min_approvals":2,"min_groups":1,"groups":{"g":["u"]},"excluded":[],` +
		`"protected":[{"path":"a/","groups":["g"],"require":[]},{"path":"e/assets.go","groups":["g"],"require":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"a/x.go", "a/x_test.go", "e/assets.go", "o/z.go"} {
		write(f)
	}
	main := &struct {
		Path string
		Main bool
	}{"m", true}
	dep := &struct {
		Path string
		Main bool
	}{"d", false}
	d := func(s string) string { return filepath.Join(root, s) }
	cases := []struct {
		name string
		pkg  goListPkg
		want []string
		disk []string // файлы, создаваемые на диске перед кейсом
		err  bool
	}{
		{"защищённый каталог", goListPkg{Dir: d("a"), Module: main, GoFiles: []string{"x.go"}}, nil, nil, false},
		{"точный файл", goListPkg{Dir: d("e"), Module: main, GoFiles: []string{"assets.go"}}, nil, nil, false},
		{"новый go", goListPkg{Dir: d("e"), Module: main, GoFiles: []string{"assets.go", "x.go"}}, []string{"e/x.go"}, []string{"e/x.go"}, false},
		{"syso", goListPkg{Dir: d("e"), Module: main, GoFiles: []string{"assets.go"}, SysoFiles: []string{"blob.syso"}}, []string{"e/blob.syso", "e/x.go"}, []string{"e/blob.syso"}, false},
		{"embed", goListPkg{Dir: d("e"), Module: main, GoFiles: []string{"assets.go"}, EmbedFiles: []string{"data.bin"}}, []string{"e/blob.syso", "e/data.bin", "e/x.go"}, []string{"e/data.bin"}, false},
		{"тест игнорируется", goListPkg{Dir: d("a"), Module: main, IgnoredGoFiles: []string{"x_test.go"}}, nil, nil, false},
		{"чужой модуль", goListPkg{Dir: d("o"), Module: dep, GoFiles: []string{"z.go"}}, nil, nil, false},
		{"вне корня", goListPkg{Dir: filepath.Dir(root), Module: main, GoFiles: []string{"q.go"}}, nil, nil, true},
	}
	for _, c := range cases {
		for _, f := range c.disk {
			write(f)
		}
		got, err := unprotectedBuildFiles(rules, root, []goListPkg{c.pkg})
		if (err != nil) != c.err {
			t.Errorf("%s: err=%v", c.name, err)
			continue
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
	}
}
