package llmrouter

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	MaxCanaryMarkers   = 256
	maxCanaryFileBytes = 64 << 10
)

// Символы, которые pyjson никогда не экранирует ни в одном режиме (ensure_ascii экранирует управляющие и > 0x7e, остальной —
// только управляющие, кавычку и обратную косую): маркер из таких символов лежит в теле запроса теми же байтами, что в тексте
// фрагмента. Поэтому поиск по сырым байтам эквивалентен поиску по декодированному тексту. Маркер надо сажать ровно в этом виде.
var canaryMarkerRe = regexp.MustCompile(`^[A-Za-z0-9@._+-]{12,128}$`)

// CanarySet — маркеры canary-секретов и ПДн (data-classes.md §5.2). nil или пустой — проверка выключена.
// Заменяет сканирование исходящего трафика на прокси: проверяются те самые байты, что уходят в POST (см. Route).
type CanarySet struct{ markers [][]byte } // в нижнем регистре ASCII

// NewCanarySet проверяет формат маркеров, дубли без учёта регистра и потолок MaxCanaryMarkers. Значения маркеров в ошибки не попадают.
func NewCanarySet(markers []string) (*CanarySet, error) {
	if len(markers) > MaxCanaryMarkers {
		return nil, fmt.Errorf("llmrouter: canary: %d маркеров, потолок %d", len(markers), MaxCanaryMarkers)
	}
	seen := make(map[string]bool, len(markers))
	c := &CanarySet{}
	for i, m := range markers {
		if !canaryMarkerRe.MatchString(m) {
			return nil, fmt.Errorf("llmrouter: canary: маркер %d: нужны 12–128 символов из [A-Za-z0-9@._+-]", i+1)
		}
		l := strings.ToLower(m)
		if seen[l] {
			return nil, fmt.Errorf("llmrouter: canary: маркер %d повторяет предыдущий (без учёта регистра)", i+1)
		}
		seen[l] = true
		c.markers = append(c.markers, []byte(l))
	}
	return c, nil
}

// LoadCanaryFile читает маркеры, по одному в строке; пустые строки и строки с '#' в начале пропускаются, CRLF допустим.
// Файл больше 64 KiB и файл без маркеров — ошибка (пустой файл не должен молча выключать проверку).
func LoadCanaryFile(path string) (*CanarySet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("llmrouter: canary: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCanaryFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("llmrouter: canary: %w", err)
	}
	if len(b) > maxCanaryFileBytes {
		return nil, fmt.Errorf("llmrouter: canary: файл больше %d байт", maxCanaryFileBytes)
	}
	var markers []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		markers = append(markers, line)
	}
	if len(markers) == 0 {
		return nil, fmt.Errorf("llmrouter: canary: в файле нет маркеров")
	}
	return NewCanarySet(markers)
}

// Len — число маркеров; nil-безопасно.
func (c *CanarySet) Len() int {
	if c == nil {
		return 0
	}
	return len(c.markers)
}

// Find ищет маркер в теле без учёта регистра ASCII; index — номер маркера в наборе. nil-безопасно.
func (c *CanarySet) Find(body []byte) (index int, ok bool) {
	if c.Len() == 0 || len(body) == 0 {
		return 0, false
	}
	low := make([]byte, len(body))
	for i, ch := range body {
		if 'A' <= ch && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		low[i] = ch
	}
	for i, m := range c.markers {
		if bytes.Contains(low, m) {
			return i, true
		}
	}
	return 0, false
}
