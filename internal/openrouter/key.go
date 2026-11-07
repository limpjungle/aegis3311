package openrouter

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxKeyFileBytes = 4 << 10

// APIKey — значение ключа. String/GoString/Format/MarshalJSON/MarshalText возвращают "***":
// случайный вывод в лог или в JSON ключа не раскрывает. Значение доступно только транспорту (неэкспортируемый метод).
type APIKey struct{ v string }

func (APIKey) String() string               { return "***" }
func (APIKey) GoString() string             { return "***" }
func (APIKey) Format(f fmt.State, _ rune)   { io.WriteString(f, "***") }
func (APIKey) MarshalJSON() ([]byte, error) { return []byte(`"***"`), nil }
func (APIKey) MarshalText() ([]byte, error) { return []byte("***"), nil }
func (k APIKey) value() string              { return k.v }

// LoadAPIKey читает файл из переменной OPENROUTER_API_KEY_FILE (getenv инжектируется).
// Переменная OPENROUTER_API_KEY не читается: ключ — только из файла (Vault agent).
// Ошибки содержат имя переменной и errno, но не содержимое файла.
func LoadAPIKey(getenv func(string) string) (APIKey, error) {
	const env = "OPENROUTER_API_KEY_FILE"
	path := getenv(env)
	if path == "" {
		return APIKey{}, fmt.Errorf("openrouter: %s не задана", env)
	}
	f, err := os.Open(path)
	if err != nil {
		return APIKey{}, fmt.Errorf("openrouter: %s: %s", env, errnoText(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return APIKey{}, fmt.Errorf("openrouter: %s: %s", env, errnoText(err))
	}
	if len(b) > maxKeyFileBytes {
		return APIKey{}, fmt.Errorf("openrouter: %s: файл больше %d байт", env, maxKeyFileBytes)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return APIKey{}, fmt.Errorf("openrouter: %s: файл пуст", env)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return APIKey{}, fmt.Errorf("openrouter: %s: ключ содержит недопустимые символы", env)
		}
	}
	return APIKey{s}, nil
}

// errnoText — текст ошибки ОС без пути файла и содержимого.
func errnoText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "ошибка чтения"
}
