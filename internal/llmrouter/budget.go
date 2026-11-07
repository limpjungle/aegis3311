package llmrouter

import (
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// Причины отказа бюджета.
const (
	denyIncident   = "budget_incident"
	denyServiceDay = "budget_service_day"
)

// budgets — счета токенов: на инцидент и на сервис за сутки UTC. USD не лимитируется (лимит расходов на ключ —
// на стороне OpenRouter, T-14). Состояние в памяти: рестарт обнуляет счета.
type budgets struct {
	mu        sync.Mutex
	cfg       BudgetConfig
	incidents map[string]*acct
	days      map[string]*dayAcct
}

type acct struct{ spent, held int64 }

type dayAcct struct {
	day string
	acct
}

func newBudgets(cfg BudgetConfig) *budgets {
	return &budgets{cfg: cfg, incidents: map[string]*acct{}, days: map[string]*dayAcct{}}
}

// forIncident возвращает Reserver, который атомарно (под одним mu) резервирует токены в обоих счетах
// сразу или ни в одном.
func (b *budgets) forIncident(incident, service string, now func() time.Time) *pairReserver {
	return &pairReserver{b: b, incident: incident, service: service, now: now}
}

func (b *budgets) closeIncident(id string) {
	b.mu.Lock()
	delete(b.incidents, id)
	b.mu.Unlock()
}

type pairReserver struct {
	b                 *budgets
	incident, service string
	now               func() time.Time
	mu                sync.Mutex
	denied            string
}

type hold struct {
	tokens int64
	inc    *acct
	day    *dayAcct
}

func (p *pairReserver) Reserve(tokens int64, _ float64) (openrouter.Hold, bool) {
	b := p.b
	b.mu.Lock()
	defer b.mu.Unlock()
	inc := b.incidents[p.incident]
	if inc == nil {
		inc = &acct{}
		b.incidents[p.incident] = inc
	}
	today := p.now().UTC().Format("2006-01-02")
	day := b.days[p.service]
	if day == nil {
		day = &dayAcct{day: today}
		b.days[p.service] = day
	} else if day.day != today { // смена суток: расход обнуляется, held переносится
		day.day, day.spent = today, 0
	}
	deny := ""
	switch {
	case inc.spent+inc.held+tokens > b.cfg.IncidentTokens:
		deny = denyIncident
	case day.spent+day.held+tokens > b.cfg.ServiceDayTokens:
		deny = denyServiceDay
	}
	if deny != "" {
		p.mu.Lock()
		p.denied = deny
		p.mu.Unlock()
		return nil, false
	}
	inc.held += tokens
	day.held += tokens
	return &hold{tokens: tokens, inc: inc, day: day}, true
}

func (p *pairReserver) Settle(h openrouter.Hold, tokens int64, _ float64) {
	hd, ok := h.(*hold)
	if !ok {
		return
	}
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	hd.inc.held -= hd.tokens
	hd.inc.spent += tokens
	hd.day.held -= hd.tokens
	hd.day.spent += tokens
}

// lastDenied — какой счёт исчерпан при последнем отказе.
func (p *pairReserver) lastDenied() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.denied
}
