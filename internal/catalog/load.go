package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	catalogdata "github.com/limpjungle/aegis3311/catalog"
	"github.com/limpjungle/aegis3311/internal/digest"
)

// Catalog — загруженный набор записей.
type Catalog struct {
	entries map[string]*Entry
	files   map[string]string // имя записи -> имя файла
	digest  string
}

// Load читает все *.yaml из корня fsys. Неизвестные поля — ошибка. Ссылки same_as разрешаются.
func Load(fsys fs.FS) (*Catalog, error) {
	paths, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	c := &Catalog{entries: map[string]*Entry{}, files: map[string]string{}}
	var errs []error
	for _, p := range paths {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		var e Entry
		if err := dec.Decode(&e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		if prev, dup := c.files[e.Name]; dup {
			errs = append(errs, fmt.Errorf("%s: имя %q уже занято файлом %s", p, e.Name, prev))
			continue
		}
		if want := strings.TrimSuffix(path.Base(p), ".yaml"); want != e.Name {
			errs = append(errs, fmt.Errorf("%s: имя файла не совпадает с name %q", p, e.Name))
		}
		c.entries[e.Name] = &e
		c.files[e.Name] = p
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if err := c.resolveSameAs(); err != nil {
		return nil, err
	}
	if c.digest, err = digest.Files(fsys, paths); err != nil {
		return nil, err
	}
	return c, nil
}

// resolveSameAs подставляет Kinds и Labels по ссылке same_as; цикл и неизвестная ссылка — ошибка.
func (c *Catalog) resolveSameAs() error {
	var errs []error
	for _, name := range c.Names() {
		e := c.entries[name]
		seen := map[string]bool{name: true}
		cur := e
		for cur.Targets.SameAs != "" {
			ref := cur.Targets.SameAs
			next, ok := c.entries[ref]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: targets.same_as ссылается на неизвестное действие %q", name, ref))
				break
			}
			if seen[ref] {
				errs = append(errs, fmt.Errorf("%s: цикл в targets.same_as через %q", name, ref))
				break
			}
			seen[ref] = true
			cur = next
		}
		if cur.Targets.SameAs != "" {
			continue // ошибка уже записана
		}
		if e.Targets.SameAs != "" {
			e.Targets = Targets{Kinds: append([]string(nil), cur.Targets.Kinds...), Labels: cloneLabels(cur.Targets.Labels)}
		}
	}
	return errors.Join(errs...)
}

func cloneLabels(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (c *Catalog) Get(name string) (*Entry, bool) {
	e, ok := c.entries[name]
	return e, ok
}

// Names возвращает имена записей в отсортированном порядке.
func (c *Catalog) Names() []string {
	names := make([]string, 0, len(c.entries))
	for n := range c.entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Digest — хеш содержимого файлов каталога.
func (c *Catalog) Digest() string { return c.digest }

// MustLoadEmbedded загружает встроенный каталог; паникует при ошибке (встроенные данные проверяются тестами).
func MustLoadEmbedded() *Catalog {
	sub, err := fs.Sub(catalogdata.FS, "actions")
	if err != nil {
		panic(err)
	}
	c, err := Load(sub)
	if err != nil {
		panic(err)
	}
	return c
}
