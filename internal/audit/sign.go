package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Signer подписывает сообщения ключом агента. Реализация для эксплуатации — KMS/HSM; здесь — Ed25519 из файла.
type Signer interface {
	KeyID() string
	Sign(msg []byte) ([]byte, error)
}

// Keyring — открытые ключи для проверки, по KeyID. Ключ, которого нет в keyring, — ошибка проверки.
type Keyring map[string]ed25519.PublicKey

// KeyID — "ed25519:" + первые 16 hex-символов sha256 открытого ключа.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}

func (k Keyring) Add(pub ed25519.PublicKey) { k[KeyID(pub)] = pub }

func (k Keyring) verify(keyID string, msg, sig []byte) error {
	pub, ok := k[keyID]
	if !ok {
		return fmt.Errorf("ключ %s не найден", keyID)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("подпись не прошла проверку")
	}
	return nil
}

// Ed25519Signer — подпись локальным ключом (разработка, тесты, офлайн-стенд).
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	id   string
}

func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{priv: priv, id: KeyID(priv.Public().(ed25519.PublicKey))}
}

func (s *Ed25519Signer) KeyID() string                   { return s.id }
func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *Ed25519Signer) Public() ed25519.PublicKey       { return s.priv.Public().(ed25519.PublicKey) }

// GenerateKey создаёт пару ключей и пишет их в PEM: приватный (PKCS#8, режим 0600, файл не должен существовать)
// и открытый (PKIX).
func GenerateKey(privPath, pubPath string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := writeNew(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if err := writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}), 0o644); err != nil {
		return nil, err
	}
	return pub, nil
}

func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadPrivateKey читает PEM PKCS#8 с ключом Ed25519.
func LoadPrivateKey(path string) (*Ed25519Signer, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: ключ не Ed25519", path)
	}
	return NewEd25519Signer(priv), nil
}

// LoadPublicKey читает PEM PKIX с открытым ключом Ed25519.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: ключ не Ed25519", path)
	}
	return pub, nil
}

func readPEM(path, typ string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != typ {
		return nil, fmt.Errorf("%s: ожидается PEM %q", path, typ)
	}
	if len(rest) != 0 && len(trimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s: данные после PEM-блока", path)
	}
	return blk.Bytes, nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
