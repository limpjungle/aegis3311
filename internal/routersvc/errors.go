package routersvc

import (
	"errors"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// ErrAnchorUnavailable — внешнее хранилище checkpoint'ов недоступно при старте: сверить цепочку нечем, старт невозможен (fail-closed).
var ErrAnchorUnavailable = errors.New("routersvc: хранилище checkpoint'ов аудита недоступно")

// Class — класс ошибки; значение совпадает с кодом выхода CLI.
type Class int

const (
	ClassFailClosed Class = 1 // store, цепочка или аудит отказали или повреждены; неизвестная ошибка
	ClassUsage      Class = 2 // аргументы, конфигурация, окружение, неинициализированный сервис
	ClassBusy       Class = 3 // файлы заняты работающим процессом
)

// ConfigError — ошибка конфигурации, секретов или окружения, обнаруженная до обращения к файлам цепочки и store.
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

// Classify относит ошибку к классу. Неизвестная ошибка — fail-closed.
func Classify(err error) Class {
	var (
		ce  *audit.ChainError
		inv *llmrouter.InvalidRequestError
		cfg *ConfigError
	)
	switch {
	case errors.Is(err, routerstate.ErrLocked), errors.Is(err, audit.ErrLocked):
		return ClassBusy
	case errors.Is(err, ErrNotInitialized), errors.As(err, &inv), errors.As(err, &cfg):
		return ClassUsage
	case errors.As(err, &ce):
		return ClassFailClosed
	}
	return ClassFailClosed
}

// Hint — действие оператора по degraded-mode.md; пусто, если подсказки нет. Не содержит секретов.
func Hint(err error) string {
	var ce *audit.ChainError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, routerstate.ErrLocked), errors.Is(err, audit.ErrLocked):
		return "файл занят другим процессом (запущен serve?): остановите сервис (systemctl stop aegis-llmrouter) и повторите"
	case errors.Is(err, routerstate.ErrCorrupt), errors.Is(err, routerstate.ErrVersion):
		return "перенесите файл store в сторону; старт с пустым store даст halt state_lost; сверьте расход по decision record'ам и сделайте resume"
	case errors.Is(err, routerstate.ErrIdentity):
		return "store другого router_id или других профилей: проверьте router_id и profiles.json"
	case errors.Is(err, ErrAnchorUnavailable):
		return "хранилище checkpoint'ов недоступно: проверьте сеть, bucket, ключи AEGIS_AUDIT_S3_* и сертификат; без сверки цепочки сервис не стартует (degraded-mode.md, anchor_unavailable)"
	case errors.As(err, &ce):
		return "цепочка повреждена: запустите aegis-audit verify и разберите нарушение (оборванную строку удаляет оператор)"
	case errors.Is(err, llmrouter.ErrAuditFailed), errors.Is(err, audit.ErrWriterFailed):
		return "аудит не принял запись: проверьте диск и ключ подписи, перезапустите сервис"
	case errors.Is(err, llmrouter.ErrStateStore), errors.Is(err, routerstate.ErrFailed):
		return "отказ записи store: проверьте диск, перезапустите сервис; после рестарта снимите остановку через resume"
	case errors.Is(err, ErrNotInitialized):
		return "сначала запустите serve: он создаёт store и цепочку"
	}
	return ""
}
