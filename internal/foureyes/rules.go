// Package foureyes — правило «четырёх глаз» для защищённых путей репозитория: какие пути защищены, какие группы людей
// могут их одобрять, и оценка одобрений PR по данным GitHub (docs/07-governance/ci-four-eyes.md).
package foureyes

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// Schema — схема .github/four-eyes.json.
const Schema = "aegisops/four-eyes/v1"

const maxGroups = 5 // назначение «человек → группа» перебирается по подмножествам групп

var (
	groupRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	loginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)
)

// Rule — защищённый путь: каталог с завершающим «/» или точный файл; groups — кто может одобрять;
// require — группы, без одобрения которых изменение не принимается.
type Rule struct {
	Path    string   `json:"path"`
	Groups  []string `json:"groups"`
	Require []string `json:"require"`
}

// Rules — содержимое .github/four-eyes.json.
type Rules struct {
	Schema       string              `json:"schema"`
	MinApprovals int                 `json:"min_approvals"`
	MinGroups    int                 `json:"min_groups"`
	Groups       map[string][]string `json:"groups"`
	Excluded     []string            `json:"excluded"` // боты и агенты: их одобрения и авторство не засчитываются
	Protected    []Rule              `json:"protected"`
}

// Load разбирает и проверяет правила: строгий JSON, непустые группы, пути без glob и без пересечений.
func Load(b []byte) (Rules, error) {
	var r Rules
	if err := strictjson.Decode(b, &r); err != nil {
		return Rules{}, fmt.Errorf("four-eyes: %w", err)
	}
	bad := func(format string, a ...any) (Rules, error) { return Rules{}, fmt.Errorf("four-eyes: "+format, a...) }
	if r.Schema != Schema {
		return bad("schema %q", r.Schema)
	}
	if r.MinApprovals < 2 || r.MinApprovals > 16 || r.MinGroups < 1 || r.MinGroups > r.MinApprovals {
		return bad("min_approvals (2..16) и min_groups (1..min_approvals) вне диапазона")
	}
	if len(r.Groups) == 0 || len(r.Groups) > maxGroups {
		return bad("groups: от 1 до %d групп", maxGroups)
	}
	if r.MinGroups > len(r.Groups) {
		return bad("min_groups больше числа групп")
	}
	for g, members := range r.Groups {
		if !groupRe.MatchString(g) {
			return bad("группа %q: недопустимое имя", g)
		}
		if len(members) == 0 {
			return bad("группа %q пуста", g)
		}
		seen := map[string]bool{}
		for _, m := range members {
			if !loginRe.MatchString(m) || seen[strings.ToLower(m)] {
				return bad("группа %q: некорректный или повторный логин %q", g, m)
			}
			seen[strings.ToLower(m)] = true
		}
	}
	for _, e := range r.Excluded {
		if !loginRe.MatchString(e) {
			return bad("excluded: некорректный логин %q", e)
		}
	}
	if len(r.Protected) == 0 {
		return bad("protected: список пуст")
	}
	for i, p := range r.Protected {
		if err := checkPath(p.Path); err != nil {
			return bad("protected[%d]: %v", i, err)
		}
		if len(p.Groups) == 0 {
			return bad("protected[%s]: groups пуст", p.Path)
		}
		in := map[string]bool{}
		for _, g := range p.Groups {
			if _, ok := r.Groups[g]; !ok {
				return bad("protected[%s]: неизвестная группа %q", p.Path, g)
			}
			if in[g] {
				return bad("protected[%s]: группа %q повторяется", p.Path, g)
			}
			in[g] = true
		}
		for _, g := range p.Require {
			if !in[g] {
				return bad("protected[%s]: require %q не входит в groups правила", p.Path, g)
			}
		}
		for _, q := range r.Protected[:i] {
			if overlaps(p.Path, q.Path) {
				return bad("пути %q и %q пересекаются", q.Path, p.Path)
			}
		}
	}
	return r, nil
}

func checkPath(p string) error {
	switch {
	case p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "*?[]\\") || strings.Contains(p, "//"):
		return fmt.Errorf("недопустимый путь %q (без glob, абсолютных путей и //)", p)
	}
	for _, seg := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("недопустимый путь %q", p)
		}
	}
	return nil
}

// overlaps: пути равны или один — каталог, содержащий другой.
func overlaps(a, b string) bool {
	return a == b || (strings.HasSuffix(a, "/") && strings.HasPrefix(b, a)) || (strings.HasSuffix(b, "/") && strings.HasPrefix(a, b))
}

// Match возвращает правило, защищающее путь (правила не пересекаются, совпадение единственное).
func (r Rules) Match(path string) (Rule, bool) {
	for _, p := range r.Protected {
		if p.Path == path || (strings.HasSuffix(p.Path, "/") && strings.HasPrefix(path, p.Path)) {
			return p, true
		}
	}
	return Rule{}, false
}

// Touched — правила, затронутые путями (без повторов, в порядке protected).
func (r Rules) Touched(paths []string) []Rule {
	hit := map[string]bool{}
	for _, p := range paths {
		if m, ok := r.Match(p); ok {
			hit[m.Path] = true
		}
	}
	var out []Rule
	for _, p := range r.Protected {
		if hit[p.Path] {
			out = append(out, p)
		}
	}
	return out
}

// GroupNames — имена групп по алфавиту.
func (r Rules) GroupNames() []string {
	out := make([]string, 0, len(r.Groups))
	for g := range r.Groups {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// Members — объединение логинов групп.
func (r Rules) Members(groups []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, m := range r.Groups[g] {
			if k := strings.ToLower(m); !seen[k] {
				seen[k] = true
				out = append(out, m)
			}
		}
	}
	return out
}
