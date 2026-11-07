package routerstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func statePath(t testing.TB) string { return filepath.Join(t.TempDir(), "state.jsonl") }

func mustOpen(t testing.TB, path string, o FileOptions) *FileStore {
	t.Helper()
	fs, err := OpenFile(path, testID, o)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	return fs
}

func mustAppend(t testing.TB, s Store, op Op) {
	t.Helper()
	if err := s.Append(op); err != nil {
		t.Fatalf("Append %s: %v", op.Kind, err)
	}
}

// runScenario записывает одну и ту же последовательность в хранилище: резервы, расходы, закрепления, failover.
func runScenario(t testing.TB, s Store, snap snapper) {
	t.Helper()
	mustAppend(t, s, nextReserve(snap, "inc-1", "svc-a", 100))
	mustAppend(t, s, settle(1, 90))
	mustAppend(t, s, nextReserve(snap, "inc-2", "svc-a", 50)) // открытый резерв
	mustAppend(t, s, Op{Kind: OpPin, At: testAt, Incident: "inc-1", Role: "primary"})
	mustAppend(t, s, intent(testEvent, downNext()))
	mustAppend(t, s, commit(testEvent))
	mustAppend(t, s, Op{Kind: OpFailoverSet, At: testAt, Failover: &Failover{Primary: EndpointState{State: "down"},
		Fallback: EndpointState{State: "up", ReqFails: 1}, Active: "fallback"}})
	mustAppend(t, s, settle(2, 30))
	mustAppend(t, s, Op{Kind: OpCloseIncident, At: testAt, Incident: "inc-missing"})
}

// splitLines — строки файла без '\n'.
func splitLines(raw []byte) [][]byte {
	return bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
}

func joinLines(ls [][]byte) []byte {
	var out []byte
	for _, l := range ls {
		out = append(append(out, l...), '\n')
	}
	return out
}

// TestFileRoundTrip: состояние после перезапуска совпадает с состоянием MemStore, получившего те же операции.
func TestFileRoundTrip(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	mem := NewMemory(testID)
	runScenario(t, fs, fs)
	runScenario(t, mem, mem)
	want := mem.Snapshot()
	if !reflect.DeepEqual(fs.Snapshot(), want) {
		t.Fatalf("до перезапуска:\nfile: %+v\nmem:  %+v", fs.Snapshot(), want)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{})
	defer fs2.Close()
	if !reflect.DeepEqual(fs2.Snapshot(), want) {
		t.Fatalf("после перезапуска:\nfile: %+v\nmem:  %+v", fs2.Snapshot(), want)
	}
}

// TestFileTornTail: оборванный хвост (без '\n' и нули) отбрасывается; повторное открытие ничего не отбрасывает.
func TestFileTornTail(t *testing.T) {
	cases := map[string]func(t *testing.T, full []byte) []byte{
		"половина строки": func(t *testing.T, full []byte) []byte { return full[:len(full)/2] },
		"37 нулевых байт": func(t *testing.T, full []byte) []byte { return make([]byte, 37) },
	}
	for name, tail := range cases {
		t.Run(name, func(t *testing.T) {
			path := statePath(t)
			fs := mustOpen(t, path, FileOptions{})
			runScenario(t, fs, fs)
			before := fs.Snapshot()
			if err := fs.Close(); err != nil {
				t.Fatal(err)
			}
			good, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			full, err := encode(99, settle(1, 1))
			if err != nil {
				t.Fatal(err)
			}
			junk := tail(t, full)
			if err := os.WriteFile(path, append(append([]byte{}, good...), junk...), 0o600); err != nil {
				t.Fatal(err)
			}

			fs2 := mustOpen(t, path, FileOptions{})
			if got := fs2.info.TruncatedBytes; got != int64(len(junk)) {
				t.Errorf("TruncatedBytes = %d, ожидается %d", got, len(junk))
			}
			if !reflect.DeepEqual(fs2.Snapshot(), before) {
				t.Errorf("состояние изменилось из-за хвоста")
			}
			if fi, _ := os.Stat(path); fi.Size() != int64(len(good)) {
				t.Errorf("размер файла %d, ожидается %d", fi.Size(), len(good))
			}
			if err := fs2.Close(); err != nil {
				t.Fatal(err)
			}
			fs3 := mustOpen(t, path, FileOptions{})
			defer fs3.Close()
			if fs3.info.TruncatedBytes != 0 {
				t.Errorf("повторное открытие отбросило %d байт", fs3.info.TruncatedBytes)
			}
		})
	}
}

// TestFileCorruptFailClosed: любая полная строка с ошибкой — ErrCorrupt, файл не меняется.
func TestFileCorruptFailClosed(t *testing.T) {
	base := statePath(t)
	fs := mustOpen(t, base, FileOptions{})
	runScenario(t, fs, fs)
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(t *testing.T, ls [][]byte) [][]byte{
		"байт изменён в середине полной строки": func(t *testing.T, ls [][]byte) [][]byte {
			ls[1] = bytes.Replace(ls[1], []byte("2026-11-07"), []byte("2026-11-08"), 1)
			return ls
		},
		"seq с пропуском": func(t *testing.T, ls [][]byte) [][]byte {
			var l line
			if err := json.Unmarshal(ls[2], &l); err != nil {
				t.Fatal(err)
			}
			ls[2], _ = json.Marshal(line{Seq: l.Seq + 1, SHA256: l.SHA256, Op: l.Op})
			return ls
		},
		"неизвестное поле в op": func(t *testing.T, ls [][]byte) [][]byte {
			var l line
			if err := json.Unmarshal(ls[1], &l); err != nil {
				t.Fatal(err)
			}
			op := append(bytes.TrimSuffix(l.Op, []byte("}")), []byte(`,"zzz":1}`)...)
			ls[1], _ = json.Marshal(line{Seq: l.Seq, SHA256: sum(op), Op: op})
			return ls
		},
		"дубль ключа в op": func(t *testing.T, ls [][]byte) [][]byte {
			var l line
			if err := json.Unmarshal(ls[1], &l); err != nil {
				t.Fatal(err)
			}
			op := bytes.Replace(l.Op, []byte(`{"kind"`), []byte(`{"kind":"reserve","kind"`), 1)
			ls[1], _ = json.Marshal(line{Seq: l.Seq, SHA256: sum(op), Op: op})
			return ls
		},
		"первая строка не снимок": func(t *testing.T, ls [][]byte) [][]byte {
			first, err := encode(1, reserve(1, "inc-1", "svc", testDay, 1))
			if err != nil {
				t.Fatal(err)
			}
			return append([][]byte{bytes.TrimSuffix(first, []byte("\n"))}, ls[1:]...)
		},
		"sha256 последней полной строки неверен": func(t *testing.T, ls [][]byte) [][]byte {
			last := len(ls) - 1
			var l line
			if err := json.Unmarshal(ls[last], &l); err != nil {
				t.Fatal(err)
			}
			l.SHA256 = "sha256:" + strings.Repeat("0", 64)
			ls[last], _ = json.Marshal(l)
			return ls
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ls := splitLines(raw)
			ls = mutate(t, append([][]byte{}, ls...))
			damaged := joinLines(ls)
			path := statePath(t)
			if err := os.WriteFile(path, damaged, 0o600); err != nil {
				t.Fatal(err)
			}
			fs, err := OpenFile(path, testID, FileOptions{})
			if err == nil {
				fs.Close()
				t.Fatal("ожидается ошибка открытия")
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("ожидается ErrCorrupt: %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, damaged) {
				t.Error("файл изменён при отказе открыть")
			}
		})
	}
}

// TestFileVersionAndIdentity: чужая версия формата и чужая идентичность роутера — отказ открытия.
func TestFileVersionAndIdentity(t *testing.T) {
	t.Run("версия v2", func(t *testing.T) {
		st := NewState(testID)
		st.Schema = "aegisops/router-state/v2"
		b, err := encode(0, Op{Kind: OpSnapshot, At: testAt, State: st})
		if err != nil {
			t.Fatal(err)
		}
		path := statePath(t)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(path, testID, FileOptions{}); !errors.Is(err, ErrVersion) {
			t.Fatalf("ожидается ErrVersion: %v", err)
		}
	})
	t.Run("чужая identity", func(t *testing.T) {
		path := statePath(t)
		fs := mustOpen(t, path, FileOptions{})
		fs.Close()
		other := Identity{RouterID: "other-router", Primary: testID.Primary, Fallback: testID.Fallback}
		if _, err := OpenFile(path, other, FileOptions{}); !errors.Is(err, ErrIdentity) {
			t.Fatalf("ожидается ErrIdentity: %v", err)
		}
		renamed := Identity{RouterID: testID.RouterID, Primary: "wafer-nvfp4", Fallback: "inceptron-fp8"}
		if _, err := OpenFile(path, renamed, FileOptions{}); !errors.Is(err, ErrIdentity) {
			t.Fatalf("смена профилей: ожидается ErrIdentity: %v", err)
		}
	})
}

// TestFileSecondWriterRejected: второй писатель на тот же журнал не открывается; после Close первого — можно.
func TestFileSecondWriterRejected(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	if _, err := OpenFile(path, testID, FileOptions{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("второй писатель: ожидается ErrLocked: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{})
	fs2.Close()
}

// TestFileOrphanHoldsRecovered: резерв без расхода списывается полностью при Load; повторный Load ничего не списывает.
func TestFileOrphanHoldsRecovered(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	mustAppend(t, fs, nextReserve(fs, "inc-1", "svc-1", 300))
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	fs2 := mustOpen(t, path, FileOptions{})
	st, info, err := fs2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if info.OrphanHolds != 1 || info.OrphanTokens != 300 {
		t.Errorf("LoadInfo: %+v", info)
	}
	if st.Incidents["inc-1"] != 300 || st.Days["svc-1"].Spent != 300 || len(st.Holds) != 0 {
		t.Errorf("состояние после Load: %+v", st)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte(`"recovered":true`)) {
		t.Error("в журнале нет settle с recovered:true")
	}
	if err := fs2.Close(); err != nil {
		t.Fatal(err)
	}

	fs3 := mustOpen(t, path, FileOptions{})
	defer fs3.Close()
	st3, info3, err := fs3.Load()
	if err != nil {
		t.Fatal(err)
	}
	if info3.OrphanHolds != 0 || st3.Incidents["inc-1"] != 300 {
		t.Errorf("повторный Load: %+v, счёт %d", info3, st3.Incidents["inc-1"])
	}
}

// TestFileCompaction: компакция сокращает журнал до снимка и нескольких операций; состояние и seq сохраняются.
func TestFileCompaction(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{CompactOps: 8})
	mem := NewMemory(testID)
	for i := 0; i < 50; i++ {
		op := nextReserve(fs, "inc-"+strconv.Itoa(i%5), "svc", 10)
		mustAppend(t, fs, op)
		mustAppend(t, mem, op)
		mustAppend(t, fs, settle(op.Hold, 10))
		mustAppend(t, mem, settle(op.Hold, 10))
	}
	raw, _ := os.ReadFile(path)
	ls := splitLines(raw)
	if !bytes.Contains(ls[0], []byte(`"kind":"snapshot"`)) {
		t.Fatalf("первая строка не снимок: %s", ls[0])
	}
	if n := len(ls) - 1; n > 8 {
		t.Errorf("после снимка %d строк, ожидается не больше 8", n)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{CompactOps: 8})
	defer fs2.Close()
	if !reflect.DeepEqual(fs2.Snapshot(), mem.Snapshot()) {
		t.Errorf("после компакции состояние отличается")
	}
	if fs2.info.Fresh {
		t.Error("после компакции Fresh = true при непустой истории")
	}
}

// TestFileCompactionKeepsHoldAndIntent: открытый резерв и неразрешённый intent переживают снимок.
func TestFileCompactionKeepsHoldAndIntent(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{CompactOps: 4})
	mustAppend(t, fs, nextReserve(fs, "inc-h", "svc", 77))
	mustAppend(t, fs, intent(testEvent, downNext()))
	for i := 0; i < 20; i++ {
		role := "primary"
		if i%2 == 1 {
			role = ""
		}
		mustAppend(t, fs, Op{Kind: OpPin, At: testAt, Incident: "inc-p", Role: role})
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if n := len(splitLines(raw)); n > 1+4 {
		t.Fatalf("компакция не сработала: %d строк", n)
	}
	fs2 := mustOpen(t, path, FileOptions{CompactOps: 4})
	defer fs2.Close()
	st := fs2.Snapshot()
	if len(st.Holds) != 1 || st.Holds[0].Tokens != 77 {
		t.Errorf("резерв потерян: %+v", st.Holds)
	}
	if st.Pending == nil || st.Pending.EventID != testEvent {
		t.Errorf("intent потерян: %+v", st.Pending)
	}
}

// TestFileCompactionCrash: мусорный tmp удаляется; отказ fsync tmp до rename — операция пишется в старый файл.
func TestFileCompactionCrash(t *testing.T) {
	t.Run("мусорный tmp удаляется при открытии", func(t *testing.T) {
		path := statePath(t)
		if err := os.WriteFile(path+".tmp", []byte("мусор"), 0o600); err != nil {
			t.Fatal(err)
		}
		fs := mustOpen(t, path, FileOptions{})
		defer fs.Close()
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("tmp не удалён: %v", err)
		}
	})
	t.Run("отказ fsync tmp до rename", func(t *testing.T) {
		path := statePath(t)
		fs := mustOpen(t, path, FileOptions{CompactOps: 2})
		fs.tmpSyncHook = func() error { return errors.New("сбой fsync tmp (тест)") }
		mem := NewMemory(testID)
		for i := 0; i < 6; i++ {
			op := nextReserve(fs, "inc-"+strconv.Itoa(i), "svc", 5)
			mustAppend(t, fs, op)
			mustAppend(t, mem, op)
		}
		if err := fs.Err(); err != nil {
			t.Fatalf("хранилище не должно отказать: %v", err)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("tmp не удалён после отказа компакции: %v", err)
		}
		raw, _ := os.ReadFile(path)
		if n := len(splitLines(raw)); n != 7 {
			t.Errorf("старый файл: %d строк, ожидается 7 (снимок и шесть операций)", n)
		}
		if err := fs.Close(); err != nil {
			t.Fatal(err)
		}
		fs2 := mustOpen(t, path, FileOptions{CompactOps: 2})
		defer fs2.Close()
		if !reflect.DeepEqual(fs2.Snapshot(), mem.Snapshot()) {
			t.Error("состояние после перезапуска отличается")
		}
	})
}

// TestFileIOFailurePoisons: ошибка fsync переводит хранилище в failed; дальше ErrFailed; после переоткрытия
// состояние — либо до операции, либо с ней (строка уже полностью записана), но не промежуточное.
func TestFileIOFailurePoisons(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	mustAppend(t, fs, nextReserve(fs, "inc-1", "svc", 10))
	before := fs.Snapshot()
	fs.syncHook = func() error { return errors.New("диск (тест)") }
	op := settle(1, 10)
	if err := fs.Append(op); !errors.Is(err, ErrFailed) {
		t.Fatalf("ожидается ErrFailed: %v", err)
	}
	if fs.Err() == nil {
		t.Fatal("Err() должен вернуть ошибку")
	}
	fs.syncHook = nil
	if err := fs.Append(settle(1, 1)); !errors.Is(err, ErrFailed) {
		t.Fatalf("следующая операция: ожидается ErrFailed: %v", err)
	}
	if _, _, err := fs.Load(); !errors.Is(err, ErrFailed) {
		t.Fatalf("Load после отказа: ожидается ErrFailed: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{})
	defer fs2.Close()
	after := fs2.Snapshot()
	withOp := before.Clone()
	if err := withOp.Apply(op); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) && !reflect.DeepEqual(after, withOp) {
		t.Errorf("после переоткрытия состояние не совпадает ни с «до», ни с «после» операции")
	}
}

// TestFileWriteFailurePoisons: ошибка записи (до fsync) — то же поведение: failed.
func TestFileWriteFailurePoisons(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	defer fs.Close()
	fs.writeHook = func() error { return errors.New("запись (тест)") }
	if err := fs.Append(nextReserve(fs, "inc-1", "svc", 10)); !errors.Is(err, ErrFailed) {
		t.Fatalf("ожидается ErrFailed: %v", err)
	}
	fs.writeHook = nil
	if err := fs.Append(nextReserve(fs, "inc-1", "svc", 10)); !errors.Is(err, ErrFailed) {
		t.Fatalf("после отказа записи хранилище должно быть failed: %v", err)
	}
	if n := len(fs.Snapshot().Holds); n != 0 {
		t.Errorf("неподтверждённая операция попала в состояние: %d резервов", n)
	}
}

// TestFileConcurrentAppend: параллельные записи (-race): номера резервов без пропусков, суммы сходятся.
func TestFileConcurrentAppend(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	const workers, perWorker, tokens = 16, 200, 7
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			inc := "inc-" + strconv.Itoa(w)
			for i := 0; i < perWorker; i++ {
				var hold uint64
				for {
					op := nextReserve(fs, inc, "svc", tokens)
					err := fs.Append(op)
					if errors.Is(err, ErrInvalidOp) { // номер занят другой горутиной: повторить
						continue
					}
					if err != nil {
						t.Errorf("reserve: %v", err)
						return
					}
					hold = op.Hold
					break
				}
				if err := fs.Append(settle(hold, tokens)); err != nil {
					t.Errorf("settle: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{})
	defer fs2.Close()
	st := fs2.Snapshot()
	total := int64(workers * perWorker * tokens)
	var sum int64
	for _, v := range st.Incidents {
		sum += v
	}
	if st.NextHold != workers*perWorker+1 || len(st.Holds) != 0 {
		t.Errorf("NextHold %d, открытых резервов %d", st.NextHold, len(st.Holds))
	}
	if sum != total || st.Days["svc"].Spent != total {
		t.Errorf("сумма по инцидентам %d, по сервису %d, ожидается %d", sum, st.Days["svc"].Spent, total)
	}
}

// TestLoadOnce: Load у FileStore — один раз.
func TestLoadOnce(t *testing.T) {
	fs := mustOpen(t, statePath(t), FileOptions{})
	defer fs.Close()
	if _, _, err := fs.Load(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.Load(); err == nil {
		t.Fatal("второй Load должен вернуть ошибку")
	}
}

// TestFileFreshMeansNoOps: Fresh — операций ещё не было. Снимок с seq > 0 (после компакции) — не Fresh.
func TestFileFreshMeansNoOps(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{CompactOps: 2})
	if !fs.info.Fresh {
		t.Error("новый файл должен быть Fresh")
	}
	for i := 0; i < 5; i++ {
		mustAppend(t, fs, nextReserve(fs, "inc-1", "svc", 1))
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{CompactOps: 2})
	if fs2.info.Fresh {
		t.Error("файл с операциями, пусть и после компакции, не Fresh")
	}
	fs2.Close()

	empty := statePath(t)
	fs3 := mustOpen(t, empty, FileOptions{})
	fs3.Close()
	fs4 := mustOpen(t, empty, FileOptions{})
	defer fs4.Close()
	if !fs4.info.Fresh {
		t.Error("файл только со снимком начального состояния должен быть Fresh")
	}
}

// FuzzOpenFile: любые байты файла — либо ошибка открытия, либо состояние, которое переживает повторное открытие.
func FuzzOpenFile(f *testing.F) {
	var seed []byte
	snap, err := encode(0, Op{Kind: OpSnapshot, At: testAt, State: NewState(testID)})
	if err != nil {
		f.Fatal(err)
	}
	seed = append(seed, snap...)
	for i, op := range []Op{reserve(1, "inc-1", "svc", testDay, 100), settle(1, 90)} {
		b, err := encode(uint64(i+1), op)
		if err != nil {
			f.Fatal(err)
		}
		seed = append(seed, b...)
	}
	f.Add(seed)
	f.Add(seed[:len(seed)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "state.jsonl")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		fs, err := OpenFile(path, testID, FileOptions{})
		if err != nil {
			return
		}
		first := fs.Snapshot()
		if err := fs.Close(); err != nil {
			t.Fatal(err)
		}
		fs2, err := OpenFile(path, testID, FileOptions{})
		if err != nil {
			t.Fatalf("повторное открытие после успешного: %v", err)
		}
		defer fs2.Close()
		if !reflect.DeepEqual(first, fs2.Snapshot()) {
			t.Fatalf("состояние меняется при повторном открытии")
		}
	})
}
