// Package bundle — подписанный манифест политик (policy bundle): какие файлы, определяющие решения агента, и с какими
// хешами одобрены ревью «четырёх глаз» и подписаны ключом CI (docs/07-governance/ci-four-eyes.md, threat-model T-24).
// Содержимое политик встроено в бинарь агента (go:embed), поэтому проверка у агента — сверка манифеста со встроенным
// содержимым: бинарь, собранный из неодобренных политик, подписанный манифест не пройдёт.
package bundle

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"

	catalogdata "github.com/limpjungle/aegis3311/catalog"
	goldensynthetic "github.com/limpjungle/aegis3311/eval/golden-synthetic"
	"github.com/limpjungle/aegis3311/internal/digest"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/policy"
)

// File — файл манифеста: путь от корня репозитория и sha256 содержимого (hex, без префикса).
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Имена дайджестов манифеста.
const (
	DigestPolicy  = "policy_bundle_digest"
	DigestCatalog = "catalog_digest"
	DigestLLM     = "llm_assets_digest"
)

// Content — содержимое, которое подписывает bundle: файлы (отсортированы по пути) и дайджесты в том виде, в каком их
// считает агент (policy_bundle_digest — как в вердикте PEP, catalog_digest — как у каталога).
type Content struct {
	Files           []File
	PolicyDigest    string
	CatalogDigest   string
	LLMAssetsDigest string
}

// source — набор файлов одного встроенного FS. dir — каталог в репозитории; embedded — то, что вшито в бинарь;
// globs — шаблоны путей внутри embedded (и внутри dir на диске); digested — какие из них входят в дайджест (nil — все).
type source struct {
	dir      string
	embedded fs.FS
	globs    []string
	digested func(fsys fs.FS, matched []string) ([]string, error)
	digest   func(Content) string
}

// sources — ЕДИНСТВЕННАЯ таблица путей bundle. Новый встроенный набор файлов добавляется здесь и в four-eyes.json.
func sources() []source {
	catalogFS, err := fs.Sub(catalogdata.FS, "actions")
	if err != nil {
		panic(err) // путь актуален, пока актуален go:embed
	}
	return []source{
		{dir: "policy", embedded: policy.FS, globs: []string{"aegis/*/*.rego"},
			digested: func(fsys fs.FS, matched []string) ([]string, error) {
				all, err := policyengine.PolicyFiles(fsys)
				if err != nil {
					return nil, err
				}
				in := map[string]bool{}
				for _, m := range matched {
					in[m] = true
				}
				var out []string
				for _, p := range all {
					if in[p] {
						out = append(out, p)
					}
				}
				return out, nil
			}},
		{dir: "catalog/actions", embedded: catalogFS, globs: []string{"*.yaml"}},
		{dir: "eval/golden-synthetic", embedded: goldensynthetic.FS,
			globs: []string{"profiles.json", "data/manifest.json", "prompt/*.md", "schema/*.json"}},
	}
}

func (s source) set(c *Content, d string) { // дайджест источника кладётся в своё поле Content
	switch s.dir {
	case "policy":
		c.PolicyDigest = d
	case "catalog/actions":
		c.CatalogDigest = d
	default:
		c.LLMAssetsDigest = d
	}
}

func (s source) read(fsys fs.FS, c *Content) error {
	var matched []string
	for _, g := range s.globs {
		m, err := fs.Glob(fsys, g)
		if err != nil {
			return err
		}
		matched = append(matched, m...)
	}
	sort.Strings(matched)
	for _, p := range matched {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		c.Files = append(c.Files, File{Path: path.Join(s.dir, p), SHA256: sha256Hex(b)})
	}
	paths := matched
	if s.digested != nil {
		var err error
		if paths, err = s.digested(fsys, matched); err != nil {
			return err
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("bundle: %s: файлов не найдено", s.dir)
	}
	d, err := digest.Files(fsys, paths)
	if err != nil {
		return err
	}
	s.set(c, d)
	return nil
}

func finish(c Content) Content {
	sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
	return c
}

// Embedded — содержимое, встроенное в бинарь.
func Embedded() (Content, error) {
	var c Content
	for _, s := range sources() {
		if err := s.read(s.embedded, &c); err != nil {
			return Content{}, err
		}
	}
	return finish(c), nil
}

// FromDir — то же по файловой системе: root — корень репозитория.
func FromDir(root string) (Content, error) {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return Content{}, fmt.Errorf("bundle: %s не каталог", root)
	}
	var c Content
	for _, s := range sources() {
		sub, err := fs.Sub(os.DirFS(root), s.dir)
		if err != nil {
			return Content{}, err
		}
		if err := s.read(sub, &c); err != nil {
			return Content{}, err
		}
	}
	return finish(c), nil
}

// Diff — человекочитаемый список отличий o от c (c — «ожидалось», o — «есть»); пусто, если содержимое совпадает.
func (c Content) Diff(o Content) []string {
	var out []string
	have := map[string]string{}
	for _, f := range o.Files {
		have[f.Path] = f.SHA256
	}
	want := map[string]bool{}
	for _, f := range c.Files {
		want[f.Path] = true
		switch h, ok := have[f.Path]; {
		case !ok:
			out = append(out, "нет файла "+f.Path)
		case h != f.SHA256:
			out = append(out, "изменён файл "+f.Path)
		}
	}
	for _, f := range o.Files {
		if !want[f.Path] {
			out = append(out, "лишний файл "+f.Path)
		}
	}
	for _, d := range []struct{ name, a, b string }{{DigestPolicy, c.PolicyDigest, o.PolicyDigest},
		{DigestCatalog, c.CatalogDigest, o.CatalogDigest}, {DigestLLM, c.LLMAssetsDigest, o.LLMAssetsDigest}} {
		if d.a != d.b {
			out = append(out, "дайджест "+d.name+" отличается")
		}
	}
	sort.Strings(out)
	return out
}

// Digests — дайджесты в виде карты манифеста.
func (c Content) Digests() map[string]string {
	return map[string]string{DigestPolicy: c.PolicyDigest, DigestCatalog: c.CatalogDigest, DigestLLM: c.LLMAssetsDigest}
}
