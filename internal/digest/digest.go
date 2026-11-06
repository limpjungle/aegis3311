// Package digest считает детерминированный хеш набора файлов (каталог, политики).
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
)

// Files возвращает "sha256:" + hex(sha256(конкатенация строк "path\x00" + hex(sha256(content)) + "\n")) по отсортированным путям.
func Files(fsys fs.FS, paths []string) (string, error) {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, p := range sorted {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return "", fmt.Errorf("digest %s: %w", p, err)
		}
		sum := sha256.Sum256(b)
		h.Write([]byte(p + "\x00" + hex.EncodeToString(sum[:]) + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
