package routersvc

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/masker"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// AuditKeyEnv — переменная с путём к приватному ключу подписи цепочки (PEM PKCS#8 Ed25519).
const AuditKeyEnv = "AEGIS_AUDIT_KEY_FILE"

// Переменные с путями к ключам доступа S3 для WORM-хранилища checkpoint'ов. Отдельная пара, не ключи kill switch;
// права: PutObject, GetObject(Version), ListBucketVersions, без Delete.
const (
	AnchorAccessKeyEnv    = "AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE"
	AnchorSecretKeyEnv    = "AEGIS_AUDIT_S3_SECRET_KEY_FILE"
	AnchorSessionTokenEnv = "AEGIS_AUDIT_S3_SESSION_TOKEN_FILE" // необязательна
)

// LoadAnchorCreds возвращает пути к ключам S3 из окружения (файлы читаются на каждый запрос, не здесь).
func LoadAnchorCreds(getenv func(string) string) s3.CredFiles {
	return s3.CredFiles{AccessKeyIDFile: getenv(AnchorAccessKeyEnv), SecretKeyFile: getenv(AnchorSecretKeyEnv),
		SessionTokenFile: getenv(AnchorSessionTokenEnv)}
}

// Secrets — секреты роутера. Любое форматирование печатает "***".
type Secrets struct {
	APIKey    openrouter.APIKey
	MaskerKey []byte
	Signer    *audit.Ed25519Signer
	// AnchorCreds — пути к ключам S3 для audit.anchor (kind "s3"); пусты, если переменные не заданы.
	AnchorCreds s3.CredFiles
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
	s.AnchorCreds = LoadAnchorCreds(getenv)
	return s, nil
}
