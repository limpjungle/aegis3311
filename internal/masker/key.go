package masker

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	maxKeyFileBytes = 4 << 10
	minKeyBytes     = 32
)

// LoadKey читает мастер-ключ псевдонимов из файла в переменной AEGIS_MASKER_KEY_FILE (getenv инжектируется):
// hex, не меньше 32 байт (64 символа). Ошибки содержат имя переменной и errno, но не путь и не содержимое файла.
func LoadKey(getenv func(string) string) ([]byte, error) {
	const env = "AEGIS_MASKER_KEY_FILE"
	path := getenv(env)
	if path == "" {
		return nil, fmt.Errorf("masker: %s не задана", env)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("masker: %s: %s", env, errnoText(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("masker: %s: %s", env, errnoText(err))
	}
	if len(b) > maxKeyFileBytes {
		return nil, fmt.Errorf("masker: %s: файл больше %d байт", env, maxKeyFileBytes)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, fmt.Errorf("masker: %s: файл пуст", env)
	}
	key, err := hex.DecodeString(s)
	if err != nil { // текст ошибки hex содержит байт из файла — не пробрасываем
		return nil, fmt.Errorf("masker: %s: ключ не в hex", env)
	}
	if len(key) < minKeyBytes {
		return nil, fmt.Errorf("masker: %s: ключ короче %d байт", env, minKeyBytes)
	}
	return key, nil
}

// errnoText — текст ошибки ОС без пути файла и содержимого.
func errnoText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "ошибка чтения"
}
