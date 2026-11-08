package intake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const StateSchema = "aegisops/intake-state/v1"

// Статусы инцидента: open — открыт, записи ещё нет; recorded — decision record записан; closing — алерты пропали,
// закрытие в роутере не подтверждено; закрытый инцидент из состояния удаляется (остаётся в Closed).
const (
	StatusOpen     = "open"
	StatusRecorded = "recorded"
	StatusClosing  = "closing"
)

var (
	ErrStateLocked  = errors.New("intake: файл состояния занят другим процессом")
	ErrStateCorrupt = errors.New("intake: файл состояния повреждён")
)

type Key struct {
	Env       string `json:"env"`
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
}

// Incident — открытый инцидент. Alerts — fingerprint → время последнего появления, не больше MaxIncidentAlerts
// (вытесняются давно не виденные, первый алерт — никогда). Alert — первый алерт группы (по нему строится секция
// alert); хранится после sanitize.
type Incident struct {
	ID           string               `json:"id"`
	Key          Key                  `json:"key"`
	FirstAlertAt time.Time            `json:"first_alert_at"`
	OpenedAt     time.Time            `json:"opened_at"`
	LastFiringAt time.Time            `json:"last_firing_at"`
	AbsentPolls  int                  `json:"absent_polls"` // подряд успешных опросов без алертов ключа
	Alerts       map[string]time.Time `json:"alerts"`
	Alert        Alert                `json:"alert"`
	Status       string               `json:"status"`
	Attempts     int                  `json:"attempts"`
}

// Data — содержимое состояния.
type Data struct {
	Schema    string               `json:"schema"`
	Incidents map[string]*Incident `json:"incidents"`
	Closed    map[string]time.Time `json:"closed"` // ID → момент закрытия; хранятся 7 суток
}

func newData() Data {
	return Data{Schema: StateSchema, Incidents: map[string]*Incident{}, Closed: map[string]time.Time{}}
}

// State — состояние intake на диске: снимок JSON, замена файла атомарна (temp → fsync → rename → fsync каталога),
// единственный процесс держит flock. path == "" — состояние только в памяти (тесты).
type State struct {
	mu   sync.Mutex
	d    Data
	path string
	lock *os.File
}

// OpenState открывает состояние. Нет файла — пустое состояние (дубли отсекает HasIncidentRecord: ID детерминирован);
// повреждённый файл — ErrStateCorrupt (процесс не стартует).
func OpenState(path string) (*State, error) {
	s := &State{d: newData(), path: path}
	if path == "" {
		return s, nil
	}
	lk, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lk); err != nil {
		lk.Close()
		return nil, fmt.Errorf("%w: %s: %w", ErrStateLocked, path, err)
	}
	s.lock = lk
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		s.Close()
		return nil, err
	}
	var d Data
	if err := strictjson.Decode(b, &d); err != nil || d.Schema != StateSchema {
		s.Close()
		if err == nil {
			err = fmt.Errorf("schema %q", d.Schema)
		}
		return nil, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	if d.Incidents == nil {
		d.Incidents = map[string]*Incident{}
	}
	if d.Closed == nil {
		d.Closed = map[string]time.Time{}
	}
	for id, inc := range d.Incidents {
		if inc == nil || inc.ID != id || (inc.Status != StatusOpen && inc.Status != StatusRecorded && inc.Status != StatusClosing) {
			s.Close()
			return nil, fmt.Errorf("%w: инцидент %q", ErrStateCorrupt, id)
		}
		if inc.Alerts == nil {
			inc.Alerts = map[string]time.Time{}
		}
		trimAlerts(inc.Alerts, inc.Alert.Fingerprint, MaxIncidentAlerts)
	}
	s.d = d
	return s, nil
}

// Do выполняет fn над данными под мьютексом и сохраняет результат. Ошибка сохранения фатальна для вызывающего:
// изменение в памяти остаётся, но дальше работать на неподтверждённом состоянии нельзя.
func (s *State) Do(fn func(d *Data)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
	return s.saveLocked()
}

// View выполняет fn над данными под мьютексом без сохранения (fn не изменяет данные).
func (s *State) View(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
}

// Get — копия инцидента; false — его нет.
func (s *State) Get(id string) (Incident, bool) {
	var out Incident
	var ok bool
	s.View(func(d *Data) {
		if inc := d.Incidents[id]; inc != nil {
			out, ok = *inc, true
			out.Alerts = make(map[string]time.Time, len(inc.Alerts))
			for k, v := range inc.Alerts {
				out.Alerts[k] = v
			}
		}
	})
	return out, ok
}

func (s *State) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(s.path))
}

// Close снимает блокировку.
func (s *State) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

var _ io.Closer = (*State)(nil)
