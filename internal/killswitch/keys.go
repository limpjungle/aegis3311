// Package killswitch — аварийная остановка LLM-контура (architecture.md §2.2, threat-model T-22).
//
// Два независимых канала (ConfigMap кластера и объект в S3) несут один и тот же документ, подписанный ed25519.
// Остановку может поставить одна подпись, а подтверждение «не остановлен» (в том числе снятие) принимается только
// при двух валидных подписях разных ключей. Подтверждение устаревает по TTL; нет свежего подтверждения — цель
// остановлена (fail-safe). Evaluate — чистая функция оценки, Monitor — опрос каналов, кэш и события аудита.
package killswitch

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// Role — роль ключа: oncall (дежурные) или renewer (автоматическое продление).
type Role string

const (
	RoleOncall  Role = "oncall"
	RoleRenewer Role = "renewer"
)

// Key — открытый ключ kill switch с привязкой к issuer'у и роли.
type Key struct {
	Pub    ed25519.PublicKey
	Issuer string
	Role   Role
}

// Keyring — ключи kill switch по audit.KeyID. Отдельный от keyring аудита: ключ агента не выпускает run.
type Keyring map[string]Key

// KeySpec — запись о ключе в конфигурации: файл открытого ключа (PEM PKIX), issuer и роль.
type KeySpec struct {
	Path   string `json:"path"`
	Issuer string `json:"issuer"`
	Role   Role   `json:"role"`
}

// LoadKeyring читает открытые ключи. Повторы key_id и issuer — ошибка; нужно не меньше двух ключей oncall,
// renewer — ноль или не меньше двух (один renewer не может ни продлить, ни проверить коллегу).
func LoadKeyring(specs []KeySpec) (Keyring, error) {
	k := Keyring{}
	issuers := map[string]bool{}
	var oncall, renewer int
	for _, s := range specs {
		switch s.Role {
		case RoleOncall:
			oncall++
		case RoleRenewer:
			renewer++
		default:
			return nil, fmt.Errorf("kill switch: ключ %s: роль %q не из oncall | renewer", s.Path, s.Role)
		}
		if !issuerRe.MatchString(s.Issuer) {
			return nil, fmt.Errorf("kill switch: ключ %s: некорректный issuer %q", s.Path, s.Issuer)
		}
		pub, err := audit.LoadPublicKey(s.Path)
		if err != nil {
			return nil, fmt.Errorf("kill switch: %w", err)
		}
		id := audit.KeyID(pub)
		if _, dup := k[id]; dup {
			return nil, fmt.Errorf("kill switch: ключ %s повторяется (%s)", id, s.Path)
		}
		if issuers[s.Issuer] {
			return nil, fmt.Errorf("kill switch: issuer %q повторяется", s.Issuer)
		}
		issuers[s.Issuer] = true
		k[id] = Key{Pub: pub, Issuer: s.Issuer, Role: s.Role}
	}
	switch {
	case oncall < 2:
		return nil, errors.New("kill switch: нужно не меньше двух ключей роли oncall")
	case renewer == 1:
		return nil, errors.New("kill switch: ключей роли renewer должно быть ноль или не меньше двух")
	}
	return k, nil
}
