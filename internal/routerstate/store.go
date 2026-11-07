package routerstate

import (
	"errors"
	"time"
)

var (
	ErrFailed    = errors.New("routerstate: хранилище остановлено после ошибки ввода-вывода")
	ErrCorrupt   = errors.New("routerstate: хранилище повреждено")
	ErrLocked    = errors.New("routerstate: хранилище занято другим писателем")
	ErrVersion   = errors.New("routerstate: неподдерживаемая версия формата")
	ErrIdentity  = errors.New("routerstate: хранилище принадлежит другому роутеру или другим профилям")
	ErrInvalidOp = errors.New("routerstate: недопустимая операция")
)

// LoadInfo — что произошло при открытии и загрузке.
type LoadInfo struct {
	Fresh          bool  // операций ещё не было (хранилище создано этим открытием или пусто)
	TruncatedBytes int64 // отброшен оборванный хвост
	OrphanHolds    int   // незакрытые резервы прошлого процесса, списаны полностью
	OrphanTokens   int64
}

// Store — состояние роутера. Append возвращает nil только после того, как операция надёжно сохранена.
// Недопустимая операция → ErrInvalidOp, store остаётся рабочим. Ошибка ввода-вывода → store переходит
// в failed навсегда, все дальнейшие вызовы возвращают ErrFailed.
// Load вызывается один раз до любых Append (MemStore допускает повтор: это имитация рестарта).
// Load списывает все незакрытые резервы (settle{recovered, tokens = hold.Tokens}) и возвращает копию состояния.
type Store interface {
	Load() (*State, LoadInfo, error)
	Append(op Op) error
	Err() error
	Close() error
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// recoverOrphans — операции списания для всех незакрытых резервов: запрос мог быть отправлен и оплачен.
func recoverOrphans(s *State, at string) []Op {
	ops := make([]Op, 0, len(s.Holds))
	for _, h := range s.Holds {
		ops = append(ops, Op{Kind: OpSettle, At: at, Hold: h.ID, Tokens: h.Tokens, Recovered: true})
	}
	return ops
}
