package routerstate

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// MaxLineBytes — потолок одной строки журнала; длиннее — ошибка и при записи, и при чтении.
// Снимок состояния длиннее лимита не записывается: компакция не происходит, журнал растёт (для MVP недостижимо).
const MaxLineBytes = 32 << 20

const (
	defaultCompactOps   = 4096
	defaultCompactBytes = 8 << 20
)

type FileOptions struct {
	CompactOps   int   // 0 → 4096 строк после снимка
	CompactBytes int64 // 0 → 8 MiB
}

// line — строка журнала. sha256 = "sha256:" + hex sha256(op).
type line struct {
	Seq    uint64          `json:"seq"`
	SHA256 string          `json:"sha256"`
	Op     json.RawMessage `json:"op"`
}

// FileStore — журнал в файле. Один писатель на файл (flock на <path>.lock).
type FileStore struct {
	mu        sync.Mutex
	path      string
	id        Identity
	lockF     *os.File
	f         *os.File
	st        *State
	seq       uint64
	sinceSnap int
	bytes     int64
	failed    error
	loaded    bool
	info      LoadInfo
	opts      FileOptions
	now       func() time.Time

	// Точки отказа для тестов пакета (nil в эксплуатации).
	writeHook   func() error // перед записью строки журнала
	syncHook    func() error // вместо fsync журнала
	tmpSyncHook func() error // вместо fsync временного файла компакции
}

// OpenFile открывает или создаёт журнал. Оборванный хвост отбрасывается; любая полная строка с ошибкой —
// ErrCorrupt; чужая версия — ErrVersion; чужая Identity — ErrIdentity; занятый файл — ErrLocked.
func OpenFile(path string, id Identity, o FileOptions) (*FileStore, error) {
	if o.CompactOps <= 0 {
		o.CompactOps = defaultCompactOps
	}
	if o.CompactBytes <= 0 {
		o.CompactBytes = defaultCompactBytes
	}
	lf, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lf); err != nil {
		lf.Close()
		return nil, fmt.Errorf("%w: %s: %v", ErrLocked, path, err)
	}
	s := &FileStore{path: path, id: id, lockF: lf, opts: o, now: time.Now}
	if err := s.open(); err != nil {
		if s.f != nil {
			s.f.Close()
		}
		lf.Close()
		return nil, err
	}
	return s, nil
}

func (s *FileStore) open() error {
	if err := os.Remove(s.path + ".tmp"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.f = f
	good, err := s.replay()
	if err != nil {
		return err
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if size > good {
		s.info.TruncatedBytes = size - good
		if err := f.Truncate(good); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	s.bytes = good
	if good == 0 { // новый файл: снимок начального состояния
		s.st, s.seq, s.info.Fresh = NewState(s.id), 0, true
		if err := s.writeSnapshot(f); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		return syncDir(filepath.Dir(s.path))
	}
	s.info.Fresh = s.seq == 0
	return nil
}

// replay читает журнал, заполняет s.st, s.seq, s.sinceSnap. Возвращает длину проверенного префикса
// (до последнего '\n').
func (s *FileStore) replay() (int64, error) {
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	br := bufio.NewReaderSize(s.f, 64<<10)
	var good int64
	for n := 1; ; n++ {
		raw, err := readLine(br)
		if err == io.EOF || err == errTorn {
			return good, nil
		}
		corrupt := func(format string, a ...any) (int64, error) {
			return 0, fmt.Errorf("%w: строка %d: %s", ErrCorrupt, n, fmt.Sprintf(format, a...))
		}
		if err != nil {
			return corrupt("%v", err)
		}
		var l line
		if err := strictjson.Decode(raw, &l); err != nil {
			return corrupt("разбор: %v", err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, l.Op); err != nil || !bytes.Equal(compact.Bytes(), l.Op) {
			return corrupt("op не в компактной форме")
		}
		if l.SHA256 != sum(l.Op) {
			return corrupt("sha256 не совпадает с содержимым")
		}
		if n == 1 {
			var peek struct {
				State struct {
					Schema string `json:"schema"`
				} `json:"state"`
			}
			if json.Unmarshal(l.Op, &peek) == nil && peek.State.Schema != "" && peek.State.Schema != Schema {
				return 0, fmt.Errorf("%w: %q", ErrVersion, peek.State.Schema)
			}
		}
		var op Op
		if err := strictjson.Decode(l.Op, &op); err != nil {
			return corrupt("разбор операции: %v", err)
		}
		if n == 1 {
			if op.Kind != OpSnapshot || op.State == nil {
				return corrupt("первая строка не снимок")
			}
			if op.State.Schema != Schema {
				return 0, fmt.Errorf("%w: %q", ErrVersion, op.State.Schema)
			}
			if err := op.State.validate(); err != nil {
				return corrupt("снимок: %v", err)
			}
			if op.State.Identity != s.id {
				return 0, ErrIdentity
			}
			s.st, s.seq = op.State, l.Seq
		} else {
			if op.Kind == OpSnapshot {
				return corrupt("снимок не в начале файла")
			}
			if l.Seq != s.seq+1 {
				return corrupt("seq %d, ожидается %d", l.Seq, s.seq+1)
			}
			if err := s.st.Apply(op); err != nil {
				return corrupt("%v", err)
			}
			s.seq = l.Seq
			s.sinceSnap++
		}
		good += int64(len(raw)) + 1
	}
}

var errTorn = errors.New("оборванная запись")

// readLine читает одну строку с '\n'. Пустой ввод — io.EOF; хвост без '\n' — errTorn; слишком длинная — ошибка.
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxLineBytes+1 {
			return nil, fmt.Errorf("строка длиннее %d байт", MaxLineBytes)
		}
		switch {
		case err == nil:
			return buf[:len(buf)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(buf) == 0 {
				return nil, io.EOF
			}
			return nil, errTorn
		default:
			return nil, err
		}
	}
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// encode собирает строку журнала (с '\n').
func encode(seq uint64, op Op) ([]byte, error) {
	b, err := json.Marshal(op)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(line{Seq: seq, SHA256: sum(b), Op: b})
	if err != nil {
		return nil, err
	}
	if len(out) > MaxLineBytes {
		return nil, invalid("строка %d байт больше потолка %d", len(out), MaxLineBytes)
	}
	return append(out, '\n'), nil
}

// writeSnapshot пишет в w снимок текущего состояния s.st с seq = s.seq и считает размер.
func (s *FileStore) writeSnapshot(w io.Writer) error {
	b, err := encode(s.seq, Op{Kind: OpSnapshot, At: stamp(s.now()), State: s.st})
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	s.bytes, s.sinceSnap = int64(len(b)), 0
	return nil
}

// Load вызывается один раз; списывает осиротевшие резервы прошлого процесса.
func (s *FileStore) Load() (*State, LoadInfo, error) {
	s.mu.Lock()
	if s.failed != nil {
		s.mu.Unlock()
		return nil, LoadInfo{}, ErrFailed
	}
	if s.loaded {
		s.mu.Unlock()
		return nil, LoadInfo{}, errors.New("routerstate: Load уже вызывался")
	}
	s.loaded = true
	for _, h := range s.st.Holds {
		s.info.OrphanHolds++
		s.info.OrphanTokens += h.Tokens
	}
	ops := recoverOrphans(s.st, stamp(s.now()))
	s.mu.Unlock()
	for _, op := range ops {
		if err := s.Append(op); err != nil {
			return nil, LoadInfo{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Clone(), s.info, nil
}

// Append применяет операцию и надёжно записывает её (fsync) до возврата.
func (s *FileStore) Append(op Op) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return ErrFailed
	}
	next := s.st.Clone()
	if err := next.Apply(op); err != nil {
		return err
	}
	if _, err := encode(s.seq+1, op); err != nil { // потолок длины: до компакции и записи
		return err
	}
	if s.sinceSnap >= s.opts.CompactOps || s.bytes >= s.opts.CompactBytes {
		if err := s.compact(); err != nil {
			return err
		}
	}
	b, _ := encode(s.seq+1, op)
	if s.writeHook != nil {
		if err := s.writeHook(); err != nil {
			s.failed = err
			return fmt.Errorf("%w: %v", ErrFailed, err)
		}
	}
	if _, err := s.f.Write(b); err != nil {
		s.failed = err
		return fmt.Errorf("%w: %v", ErrFailed, err)
	}
	if err := s.sync(); err != nil {
		s.failed = err
		return fmt.Errorf("%w: %v", ErrFailed, err)
	}
	s.st, s.seq = next, s.seq+1
	s.sinceSnap++
	s.bytes += int64(len(b))
	return nil
}

func (s *FileStore) sync() error {
	if s.syncHook != nil {
		return s.syncHook()
	}
	return s.f.Sync()
}

// compact переписывает файл: снимок текущего состояния в <path>.tmp, fsync, rename поверх журнала, fsync каталога.
// Ошибка до rename — работа продолжается со старым файлом; после — хранилище failed (на диске корректный файл).
func (s *FileStore) compact() error {
	tmp := s.path + ".tmp"
	abort := func() error { // старый файл цел: компакция откладывается до следующей операции
		os.Remove(tmp)
		return nil
	}
	tf, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return abort()
	}
	oldBytes, oldSince := s.bytes, s.sinceSnap
	if err := s.writeSnapshot(tf); err != nil {
		tf.Close()
		s.bytes, s.sinceSnap = oldBytes, oldSince
		return abort()
	}
	newBytes := s.bytes
	s.bytes, s.sinceSnap = oldBytes, oldSince
	if s.tmpSyncHook != nil {
		err = s.tmpSyncHook()
	} else {
		err = tf.Sync()
	}
	if cerr := tf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return abort()
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return abort()
	}
	fail := func(err error) error {
		s.failed = err
		return fmt.Errorf("%w: компакция: %v", ErrFailed, err)
	}
	if err := syncDir(filepath.Dir(s.path)); err != nil {
		return fail(err)
	}
	nf, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return fail(err)
	}
	s.f.Close()
	s.f, s.bytes, s.sinceSnap = nf, newBytes, 0
	return nil
}

func (s *FileStore) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// Snapshot — копия текущего состояния (для тестов и диагностики).
func (s *FileStore) Snapshot() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Clone()
}

// Close закрывает журнал и снимает блокировку. Дальнейшие вызовы возвращают ErrFailed.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	if cerr := s.lockF.Close(); err == nil {
		err = cerr
	}
	if s.failed == nil {
		s.failed = errors.New("хранилище закрыто")
	}
	return err
}
