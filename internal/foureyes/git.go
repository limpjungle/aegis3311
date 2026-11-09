package foureyes

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

var revRe = regexp.MustCompile(`^[0-9a-fA-F]{40}(\^)?$|^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}(\^)?$|^HEAD$`)

// git выполняет git -C gitDir ... и возвращает stdout. Ревизии проверяются: ничего, похожего на опцию.
func git(gitDir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", gitDir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func checkRev(rev string) error {
	if !revRe.MatchString(rev) {
		return fmt.Errorf("git: недопустимая ревизия %q", rev)
	}
	return nil
}

// ProtectedTree — защищённые файлы ревизии: путь → "режим blob-sha" (git ls-tree -r -z --full-tree).
func ProtectedTree(gitDir, rev string, r Rules) (map[string]string, error) {
	if err := checkRev(rev); err != nil {
		return nil, err
	}
	b, err := git(gitDir, "ls-tree", "-r", "-z", "--full-tree", rev)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, rec := range bytes.Split(b, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, ok := strings.Cut(string(rec), "\t") // "<mode> <type> <sha>\t<path>"
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("git ls-tree: неожиданная запись %q", rec)
		}
		if _, prot := r.Match(path); prot {
			out[path] = f[0] + " " + f[2] // режим входит в сравнение: смена исполняемого бита — изменение
		}
	}
	return out, nil
}

// ChangedProtected — защищённые пути, содержимое или режим которых различаются в ревизиях a и b (отсортированы).
func ChangedProtected(gitDir, a, b string, r Rules) ([]string, error) {
	ta, err := ProtectedTree(gitDir, a, r)
	if err != nil {
		return nil, err
	}
	tb, err := ProtectedTree(gitDir, b, r)
	if err != nil {
		return nil, err
	}
	var out []string
	for p, v := range ta {
		if tb[p] != v {
			out = append(out, p)
		}
	}
	for p := range tb {
		if _, ok := ta[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Show возвращает содержимое файла в ревизии (git show rev:path).
func Show(gitDir, rev, path string) ([]byte, error) {
	if err := checkRev(rev); err != nil {
		return nil, err
	}
	return git(gitDir, "show", rev+":"+path)
}

// RevParse возвращает полный SHA коммита ревизии.
func RevParse(gitDir, rev string) (string, error) {
	if err := checkRev(rev); err != nil {
		return "", err
	}
	b, err := git(gitDir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
