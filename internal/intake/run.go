package intake

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Service — цикл intake: опрос Alertmanager → Tracker → очередь обработки → закрытие.
type Service struct {
	Cfg     Config
	D       Durations
	Alerts  AlertSource
	State   *State
	Tracker *Tracker
	Pipe    *Pipeline
	Router  Router
	Log     *slog.Logger
	Now     func() time.Time
	// DispatchEvery — период проверки готовых к обработке инцидентов; 0 → min(poll_interval, 1 с).
	DispatchEvery time.Duration

	mu       sync.Mutex
	inflight map[string]bool // инцидент в очереди или в обработке: пока он там, его не закрывают
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run работает до отмены ctx (результат nil) или фатальной ошибки (аудит, store роутера, состояние intake).
// Журнал содержит только ID, статусы и счётчики: значения фрагментов и тексты алертов не логируются.
func (s *Service) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.inflight = map[string]bool{}
	jobs := make(chan string, s.Cfg.MaxOpenIncidents+1)
	errCh := make(chan error, s.Cfg.Workers+1)
	var wg sync.WaitGroup
	for range s.Cfg.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				var err error
				if ctx.Err() == nil { // остановка: оставшиеся в очереди обработает следующий запуск
					err = s.handle(ctx, id)
				}
				s.mu.Lock()
				delete(s.inflight, id)
				s.mu.Unlock()
				if err != nil {
					errCh <- err
					cancel()
				}
			}
		}()
	}
	fatal := func() error {
		cancel()
		close(jobs)
		wg.Wait()
		close(errCh)
		var errs []error
		for e := range errCh {
			errs = append(errs, e)
		}
		return errors.Join(errs...)
	}

	every := s.DispatchEvery
	if every <= 0 {
		every = min(s.D.Poll, time.Second)
	}
	pollT, dispT, cleanT := time.NewTicker(s.D.Poll), time.NewTicker(every), time.NewTicker(24*time.Hour)
	defer pollT.Stop()
	defer dispT.Stop()
	defer cleanT.Stop()
	s.cleanup()
	if err := s.poll(ctx); err != nil {
		errCh <- err
		return fatal()
	}
	s.closeResolved(ctx)
	for {
		s.dispatch(jobs)
		select {
		case <-ctx.Done():
			return fatal()
		case <-pollT.C:
			if err := s.poll(ctx); err != nil {
				errCh <- err
				return fatal()
			}
			s.closeResolved(ctx)
		case <-dispT.C:
		case <-cleanT.C:
			s.cleanup()
		}
	}
}

func (s *Service) handle(ctx context.Context, id string) error {
	inc, ok := s.State.Get(id)
	if !ok {
		return nil
	}
	return s.Pipe.Handle(ctx, &inc)
}

// poll — один опрос. Ошибка опроса не фатальна и инциденты не трогает (недоступность Alertmanager не разрешение);
// фатальна только ошибка сохранения состояния.
func (s *Service) poll(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(ctx, s.D.Poll)
	firing, err := s.Alerts.Firing(pctx)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			s.log().Warn("intake_poll_failed", "class", sourceClass(err))
		}
		return nil
	}
	for i := range firing {
		firing[i] = SanitizeAlert(firing[i])
	}
	opened, _, err := s.Tracker.Observe(s.now(), firing)
	if err != nil {
		return err
	}
	for _, inc := range opened {
		s.log().Info("intake_incident_opened", "incident", inc.ID, "service", inc.Key.Service, "namespace", inc.Key.Namespace)
	}
	return nil
}

// dispatch ставит в очередь готовые к обработке инциденты: открытые с наступившим T0 (открытие + settle) и закрываемые
// без записи (по ним пишется resolved_before_collect).
func (s *Service) dispatch(jobs chan<- string) {
	now := s.now()
	var due []string
	s.State.View(func(d *Data) {
		for id, inc := range d.Incidents {
			if (inc.Status == StatusOpen && !now.Before(inc.OpenedAt.Add(s.D.Settle))) ||
				(inc.Status == StatusClosing && !s.Pipe.Writer.HasIncidentRecord(id)) {
				due = append(due, id)
			}
		}
	})
	for _, id := range due {
		s.mu.Lock()
		busy := s.inflight[id]
		if !busy {
			s.inflight[id] = true
		}
		s.mu.Unlock()
		if busy {
			continue
		}
		select {
		case jobs <- id:
		default: // очередь полна: следующий проход
			s.mu.Lock()
			delete(s.inflight, id)
			s.mu.Unlock()
		}
	}
}

// closeResolved закрывает в роутере инциденты в состоянии closing, по которым запись есть и обработка не идёт.
// Ошибка CloseIncident (роутер остановлен из-за store) — повтор на следующем проходе.
func (s *Service) closeResolved(ctx context.Context) {
	var ids []string
	s.State.View(func(d *Data) {
		for id, inc := range d.Incidents {
			if inc.Status == StatusClosing && s.Pipe.Writer.HasIncidentRecord(id) {
				ids = append(ids, id)
			}
		}
	})
	for _, id := range ids {
		s.mu.Lock()
		busy := s.inflight[id]
		s.mu.Unlock()
		if busy || ctx.Err() != nil {
			continue
		}
		if err := s.Router.CloseIncident(id); err != nil {
			s.log().Warn("intake_close_failed", "incident", id, "error", err.Error())
			continue
		}
		now := s.now().UTC()
		if err := s.State.Do(func(d *Data) {
			delete(d.Incidents, id)
			d.Closed[id] = now
		}); err != nil {
			s.log().Error("intake_state_failed", "error", err.Error())
			return
		}
		s.log().Info("intake_incident_closed", "incident", id)
	}
}

// cleanup удаляет снимки входа старше snapshot_retention.
func (s *Service) cleanup() {
	n, err := CleanSnapshots(s.Cfg.SnapshotDir, s.D.SnapshotRetention, s.now())
	if err != nil {
		s.log().Warn("intake_snapshot_cleanup_failed", "error", err.Error())
	}
	if n > 0 {
		s.log().Info("intake_snapshots_removed", "count", n)
	}
}

// CleanSnapshots удаляет файлы *.json старше retention (по времени изменения); возвращает их число.
func CleanSnapshots(dir string, retention time.Duration, now time.Time) (int, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) <= retention {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n, nil
}
