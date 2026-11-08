package audit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// ErrWriterFailed — Writer остановлен после ошибки записи (fail-closed). Нужна проверка и ручной разбор файла.
var ErrWriterFailed = errors.New("запись аудита остановлена после ошибки")

// ErrLocked — файл цепочки занят другим писателем (flock).
var ErrLocked = errors.New("audit: файл цепочки занят другим писателем")

// Writer добавляет decision record'ы, события роутера и события kill switch в файл цепочки (JSONL, только дописывание).
// Один писатель на файл: при открытии берётся эксклюзивная блокировка (flock).
type Writer struct {
	mu     sync.Mutex
	f      *os.File
	signer Signer
	head   Head
	failed error
	now    func() time.Time
	events map[string]struct{} // event_id событий роутера в цепочке
	last   *RouterEvent        // последнее событие роутера в цепочке
	lastKS *KillSwitchEvent    // последнее событие kill switch в цепочке
	log    []RouterEvent       // все события роутера в порядке цепочки
	incs   map[string]struct{} // incident.id decision record'ов в цепочке
}

// OpenWriter открывает или создаёт файл цепочки. Существующий файл проверяется целиком (Verify с keys);
// любое нарушение, включая оборванную последнюю строку, — ошибка: дописывать в повреждённую цепочку нельзя.
// Ключ signer должен быть в keys.
func OpenWriter(path, chainID string, signer Signer, keys Keyring) (*Writer, error) {
	if !chainRe.MatchString(chainID) {
		return nil, fmt.Errorf("некорректный chain_id %q", chainID)
	}
	if _, ok := keys[signer.KeyID()]; !ok {
		return nil, fmt.Errorf("ключ подписи %s отсутствует в keyring", signer.KeyID())
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %s: %w", ErrLocked, path, err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	events := map[string]struct{}{}
	var last *RouterEvent
	var lastKS *KillSwitchEvent
	var log []RouterEvent
	incs := map[string]struct{}{}
	head, err := Verify(f, keys, VerifyOptions{ChainID: chainID, OnRouterEvent: func(_ uint64, ev *RouterEvent) {
		events[ev.EventID], last = struct{}{}, ev
		log = append(log, *ev)
	}, OnRecord: func(_ uint64, rec *DecisionRecord) { incs[rec.Incident.ID] = struct{}{} },
		OnKillSwitchEvent: func(_ uint64, ev *KillSwitchEvent) { events[ev.EventID], lastKS = struct{}{}, ev }})
	if err != nil {
		f.Close()
		return nil, err
	}
	if head.Seq == 0 {
		head.ChainID = chainID
		// Новый файл: фиксируем создание записи каталога, иначе после сбоя файл может пропасть.
		if err := syncDir(filepath.Dir(path)); err != nil {
			f.Close()
			return nil, err
		}
	}
	return &Writer{f: f, signer: signer, head: head, now: time.Now, events: events, last: last, lastKS: lastKS, log: log, incs: incs}, nil
}

// Head — текущая голова цепочки.
func (w *Writer) Head() Head {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head
}

// Append проверяет запись, добавляет её в цепочку и делает fsync. Ошибка возвращается до того, как
// решение может считаться записанным; после ошибки ввода-вывода Writer больше ничего не принимает.
func (w *Writer) Append(rec *DecisionRecord) (Entry, error) {
	if err := w.usable(); err != nil {
		return Entry{}, err
	}
	if err := rec.Validate(); err != nil {
		return Entry{}, fmt.Errorf("decision record: %w", err)
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return Entry{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	e, err := w.appendBodyLocked(body)
	if err == nil {
		w.incs[rec.Incident.ID] = struct{}{}
	}
	return e, err
}

// HasIncidentRecord — есть ли в цепочке decision record этого инцидента. Страховка идемпотентности intake
// после краха между Append и сохранением его состояния.
func (w *Writer) HasIncidentRecord(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.incs[id]
	return ok
}

// AppendEvent проверяет событие роутера и добавляет его в ту же цепочку (второй тип записи).
func (w *Writer) AppendEvent(ev *RouterEvent) (Entry, error) {
	if err := w.usable(); err != nil {
		return Entry{}, err
	}
	if err := ev.Validate(); err != nil {
		return Entry{}, fmt.Errorf("router event: %w", err)
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return Entry{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, dup := w.events[ev.EventID]; dup { // Verify отвергает дубль: цепочка перестала бы открываться
		return Entry{}, fmt.Errorf("router event: event_id %q уже в цепочке", ev.EventID)
	}
	e, err := w.appendBodyLocked(body)
	if err != nil {
		return e, err
	}
	w.events[ev.EventID] = struct{}{}
	cp := *ev
	w.last = &cp
	w.log = append(w.log, cp)
	return e, nil
}

// AppendKillSwitchEvent проверяет событие kill switch и добавляет его в ту же цепочку (третий тип записи).
func (w *Writer) AppendKillSwitchEvent(ev *KillSwitchEvent) (Entry, error) {
	if err := w.usable(); err != nil {
		return Entry{}, err
	}
	if err := ev.Validate(); err != nil {
		return Entry{}, fmt.Errorf("kill switch event: %w", err)
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return Entry{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, dup := w.events[ev.EventID]; dup {
		return Entry{}, fmt.Errorf("kill switch event: event_id %q уже в цепочке", ev.EventID)
	}
	e, err := w.appendBodyLocked(body)
	if err != nil {
		return e, err
	}
	w.events[ev.EventID] = struct{}{}
	cp := *ev
	w.lastKS = &cp
	return e, nil
}

// LastKillSwitchEvent — последнее событие kill switch в цепочке; false — событий нет.
func (w *Writer) LastKillSwitchEvent() (KillSwitchEvent, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastKS == nil {
		return KillSwitchEvent{}, false
	}
	return *w.lastKS, true
}

// HasEvent — есть ли в цепочке событие роутера с этим event_id.
func (w *Writer) HasEvent(eventID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.events[eventID]
	return ok
}

// RouterEvents — копия всех событий роутера в порядке цепочки: по ним восстанавливается состояние failover.
func (w *Writer) RouterEvents() []RouterEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]RouterEvent(nil), w.log...)
}

// ChainNonEmpty — есть ли в цепочке хоть одна запись (decision record или событие роутера).
func (w *Writer) ChainNonEmpty() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head.Seq > 0
}

// LastRouterEvent — последнее событие роутера в цепочке; false — событий нет.
func (w *Writer) LastRouterEvent() (RouterEvent, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.last == nil {
		return RouterEvent{}, false
	}
	return *w.last, true
}

func (w *Writer) usable() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return fmt.Errorf("%w: %v", ErrWriterFailed, w.failed)
	}
	return nil
}

// appendBody подписывает и записывает уже проверенное тело записи.
func (w *Writer) appendBody(body []byte) (Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendBodyLocked(body)
}

// appendBodyLocked — appendBody под w.mu.
func (w *Writer) appendBodyLocked(body []byte) (Entry, error) {
	if w.failed != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrWriterFailed, w.failed)
	}
	e := Entry{Schema: EntrySchema, ChainID: w.head.ChainID, Seq: w.head.Seq + 1, PrevHash: w.head.Hash,
		RecordSHA256: sha256Prefixed(body), KeyID: w.signer.KeyID(), Record: body}
	e.Hash = entryHash(e.ChainID, e.Seq, e.PrevHash, e.RecordSHA256)
	sig, err := w.signer.Sign(entrySigMsg(e.Hash))
	if err != nil {
		// Подпись не получена — в файл ничего не ушло, но без подписи писать нельзя: останавливаемся.
		w.failed = fmt.Errorf("подпись: %w", err)
		return Entry{}, fmt.Errorf("%w: %v", ErrWriterFailed, w.failed)
	}
	e.Sig = base64.StdEncoding.EncodeToString(sig)
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if len(line) > MaxLineBytes {
		return Entry{}, fmt.Errorf("запись %d байт больше потолка %d", len(line), MaxLineBytes)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		w.failed = err
		return Entry{}, fmt.Errorf("%w: %v", ErrWriterFailed, err)
	}
	if err := w.f.Sync(); err != nil {
		w.failed = err
		return Entry{}, fmt.Errorf("%w: %v", ErrWriterFailed, err)
	}
	w.head.Seq, w.head.Hash = e.Seq, e.Hash
	return e, nil
}

// Checkpoint подписывает текущую голову цепочки (для передачи в Anchor).
func (w *Writer) Checkpoint() (Checkpoint, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return Checkpoint{}, fmt.Errorf("%w: %v", ErrWriterFailed, w.failed)
	}
	return SignCheckpoint(w.head, w.now(), w.signer)
}

// Close снимает блокировку и закрывает файл.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	if w.failed == nil {
		w.failed = errors.New("writer закрыт")
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Anchor — внешнее хранилище checkpoint'ов (WORM с object lock или transparency log).
// Реализация обязана отказывать в перезаписи уже сохранённого checkpoint'а.
type Anchor interface {
	Put(c Checkpoint) error
}

// DirAnchor — checkpoint'ы файлами в каталоге, без перезаписи (O_EXCL). Для разработки и тестов;
// в эксплуатации — объектное хранилище с object lock в режиме compliance.
type DirAnchor struct{ Dir string }

func (a DirAnchor) Put(c Checkpoint) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	name := filepath.Join(a.Dir, fmt.Sprintf("%s-%020d.json", c.ChainID, c.Seq))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
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
	return syncDir(a.Dir)
}

// LoadCheckpoints читает все checkpoint'ы цепочки chainID из каталога DirAnchor (без проверки подписи:
// её делает Verify).
func (a DirAnchor) LoadCheckpoints(chainID string) ([]Checkpoint, error) {
	paths, err := filepath.Glob(filepath.Join(a.Dir, chainID+"-*.json"))
	if err != nil {
		return nil, err
	}
	var out []Checkpoint
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var c Checkpoint
		if err := strictjson.Decode(b, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if c.ChainID == chainID { // префикс имени может совпасть у цепочек "a" и "a-b"
			out = append(out, c)
		}
	}
	return out, nil
}
