package routersvc

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/masker"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// AuditKeyEnv — переменная с путём к приватному ключу подписи цепочки (PEM PKCS#8 Ed25519).
const AuditKeyEnv = "AEGIS_AUDIT_KEY_FILE"

// Secrets — секреты роутера. Любое форматирование печатает "***".
type Secrets struct {
	APIKey    openrouter.APIKey
	MaskerKey []byte
	Signer    *audit.Ed25519Signer
}

func (Secrets) String() string             { return "***" }
func (Secrets) GoString() string           { return "***" }
func (Secrets) Format(f fmt.State, _ rune) { io.WriteString(f, "***") }

// LoadSecrets читает ключи из файлов в переменных OPENROUTER_API_KEY_FILE, AEGIS_MASKER_KEY_FILE, AEGIS_AUDIT_KEY_FILE.
// Ошибки содержат имя переменной и errno, но не путь и не содержимое файла.
func LoadSecrets(getenv func(string) string) (Secrets, error) {
	var s Secrets
	var err error
	if s.APIKey, err = openrouter.LoadAPIKey(getenv); err != nil {
		return Secrets{}, err
	}
	if s.MaskerKey, err = masker.LoadKey(getenv); err != nil {
		return Secrets{}, err
	}
	path := getenv(AuditKeyEnv)
	if path == "" {
		return Secrets{}, fmt.Errorf("audit: %s не задана", AuditKeyEnv)
	}
	if s.Signer, err = audit.LoadPrivateKey(path); err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return Secrets{}, fmt.Errorf("audit: %s: %s", AuditKeyEnv, pe.Err)
		}
		return Secrets{}, fmt.Errorf("audit: %s: ожидается PEM PKCS#8 с ключом Ed25519", AuditKeyEnv)
	}
	return s, nil
}
