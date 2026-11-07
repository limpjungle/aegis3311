package llmrouter

import (
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Причины отказа бюджета.
const (
	denyIncident   = "budget_incident"
	denyServiceDay = "budget_service_day"
	// denyStateStore — резерв не записан в хранилище состояния: запрос не отправляется (fail-closed).
	denyStateStore = "state_store"
)

const dayFormat = "2006-01-02"

// budgets — счета токенов: на инцидент и на сервис за сутки UTC. USD не лимитируется (лимит расходов на ключ —
// на стороне OpenRouter, T-14). Счета зеркалируются в routerstate.Store: резерв пишется до отправки запроса,
// расход — после ответа, рестарт процесса счета не обнуляет.
type budgets struct {
	mu        sync.Mutex
	cfg       BudgetConfig
	st        routerstate.Store
	incidents map[string]*acct
	days      map[string]*dayAcct
	nextHold  uint64
}

type acct struct{ spent, held int64 }

type dayAcct struct {
	day string
	acct
}

// newBudgets строит счета из загруженного состояния (после Load резервов нет: held == 0).
func newBudgets(cfg BudgetConfig, st routerstate.Store, s *routerstate.State) *budgets {
	b := &budgets{cfg: cfg, st: st, incidents: map[string]*acct{}, days: map[string]*dayAcct{}, nextHold: s.NextHold}
	for id, spent := range s.Incidents {
		b.incidents[id] = &acct{spent: spent}
	}
	for svc, d := range s.Days {
		b.days[svc] = &dayAcct{day: d.Day, acct: acct{spent: d.Spent}}
	}
	return b
}

// laterDay — более поздние из двух суток YYYY-MM-DD (сравнение строк): при уходе часов назад счёт не сбрасывается.
func laterDay(a, b string) string {
	if a > b {
		return a
	}
	return b
}

// forIncident возвращает Reserver, который атомарно (под одним mu) резервирует токены в обоих счетах
// сразу или ни в одном.
func (b *budgets) forIncident(incident, service string, now func() time.Time) *pairReserver {
	return &pairReserver{b: b, incident: incident, service: service, now: now}
}

func (b *budgets) closeIncident(id string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.st.Append(routerstate.Op{Kind: routerstate.OpCloseIncident, At: audit.Timestamp(now), Incident: id}); err != nil {
		return err
	}
	delete(b.incidents, id)
	return nil
}

type pairReserver struct {
	b                 *budgets
	incident, service string
	now               func() time.Time
	mu                sync.Mutex
	denied            string
	storeErr          error
}

type hold struct {
	id                uint64
	tokens            int64
	inc               *acct
	day               *dayAcct
	incident, service string
}

func (p *pairReserver) deny(reason string, storeErr error) {
	p.mu.Lock()
	p.denied = reason
	p.mu.Unlock()
	if storeErr != nil {
		p.setStoreErr(storeErr)
	}
}

func (p *pairReserver) Reserve(tokens int64, _ float64) (openrouter.Hold, bool) {
	b := p.b
	b.mu.Lock()
	defer b.mu.Unlock()
	now := p.now().UTC()
	today := now.Format(dayFormat)
	inc, day := b.incidents[p.incident], b.days[p.service]
	// Эффективные сутки без мутации: смена суток вперёд обнуляет расход, held переносится.
	effDay, effSpent := today, int64(0)
	if day != nil {
		effDay = laterDay(day.day, today)
		if effDay == day.day {
			effSpent = day.spent
		}
	}
	var incSpent, incHeld, dayHeld int64
	if inc != nil {
		incSpent, incHeld = inc.spent, inc.held
	}
	if day != nil {
		dayHeld = day.held
	}
	switch {
	case incSpent+incHeld+tokens > b.cfg.IncidentTokens:
		p.deny(denyIncident, nil)
		return nil, false
	case effSpent+dayHeld+tokens > b.cfg.ServiceDayTokens:
		p.deny(denyServiceDay, nil)
		return nil, false
	}
	id := b.nextHold
	if err := b.st.Append(routerstate.Op{Kind: routerstate.OpReserve, At: audit.Timestamp(now), Hold: id, Incident: p.incident,
		Service: p.service, Day: effDay, Tokens: tokens}); err != nil {
		p.deny(denyStateStore, err)
		return nil, false
	}
	if inc == nil {
		inc = &acct{}
		b.incidents[p.incident] = inc
	}
	if day == nil {
		day = &dayAcct{day: effDay}
		b.days[p.service] = day
	} else if effDay != day.day {
		day.day, day.spent = effDay, 0
	}
	b.nextHold++
	inc.held += tokens
	day.held += tokens
	return &hold{id: id, tokens: tokens, inc: inc, day: day, incident: p.incident, service: p.service}, true
}

func (p *pairReserver) Settle(h openrouter.Hold, tokens int64, _ float64) {
	hd, ok := h.(*hold)
	if !ok {
		return
	}
	b := p.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if tokens < 0 { // отрицательный расход невозможен: списывается весь резерв
		tokens = hd.tokens
	}
	hd.inc.held -= hd.tokens
	// Расход идёт в счёт, который существует сейчас (как в store: закрытый инцидент расход не получает, открытый
	// заново с тем же именем — получает), а не в тот, где был сделан резерв.
	if cur := b.incidents[hd.incident]; cur != nil {
		cur.spent += tokens
	}
	hd.day.held -= hd.tokens
	hd.day.spent += tokens
	// Память не откатывается при сбое записи: при рестарте резерв считается осиротевшим и списывается полностью.
	// Отказ settle (в том числе ErrInvalidOp) — расхождение памяти со store: роутер останавливается (settleError).
	if err := b.st.Append(routerstate.Op{Kind: routerstate.OpSettle, At: audit.Timestamp(p.now()), Hold: hd.id, Tokens: tokens}); err != nil {
		p.setStoreErr(settleError{err})
	}
}

// settleError — отказ store при записи расхода: haltStoreLocked останавливает роутер и при ErrInvalidOp.
type settleError struct{ error }

func (e settleError) Unwrap() error { return e.error }

func (p *pairReserver) setStoreErr(err error) {
	p.mu.Lock()
	if p.storeErr == nil {
		p.storeErr = err
	}
	p.mu.Unlock()
}

// lastDenied — какой счёт исчерпан при последнем отказе.
func (p *pairReserver) lastDenied() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.denied
}

// storeFailed — первая ошибка хранилища состояния за время жизни Reserver'а; nil — ошибок не было.
func (p *pairReserver) storeFailed() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.storeErr
}
