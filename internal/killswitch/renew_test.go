package killswitch

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
)

type memChan struct {
	name string
	raw  []byte
	err  error
}

func (m *memChan) Read(context.Context) ([]byte, error)      { return m.raw, m.err }
func (m *memChan) Publish(_ context.Context, b []byte) error { m.raw = b; return nil }
func (m *memChan) Name() string                              { return m.name }

type memSigs map[string][]byte

func (m memSigs) Put(_ context.Context, k string, b []byte) error { m[k] = b; return nil }
func (m memSigs) Get(_ context.Context, k string) ([]byte, error) {
	if b, ok := m[k]; ok {
		return b, nil
	}
	return nil, &s3.Error{Kind: "http_404"}
}

func TestRenewTwoRenewers(t *testing.T) {
	tk := newTKeys(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 8, 10, 20, 0, 0, time.UTC)
	cfg := RenewConfig{Slot: time.Hour, TTL: 6 * time.Hour, Prefix: "renew/"}
	cm, oob := &memChan{name: "configmap", raw: tk.doc(t, false, nil, nil, now.Add(-3*time.Hour), 6*time.Hour, "a", "b")}, &memChan{name: "oob"}
	oob.raw = cm.raw
	sigs := memSigs{}
	chans := []ChannelIO{cm, oob}
	r, err := Renew(ctx, now, cfg, tk.signers["r1"], tk.ring, chans, sigs, ParseOptions{})
	if err != nil || r.Action != "waiting_peer" || len(sigs) != 1 {
		t.Fatalf("первый: %+v %v", r, err)
	}
	r, err = Renew(ctx, now.Add(time.Minute), cfg, tk.signers["r2"], tk.ring, chans, sigs, ParseOptions{})
	if err != nil || r.Action != "published" {
		t.Fatalf("второй: %+v %v", r, err)
	}
	if string(cm.raw) != string(oob.raw) || tk.parse(t, cm.raw).Confirmation("c1") != "renewer" {
		t.Error("каналы расходятся или подтверждение не renewer")
	}
	r, err = Renew(ctx, now.Add(2*time.Minute), cfg, tk.signers["r1"], tk.ring, chans, sigs, ParseOptions{})
	if err != nil || r.Action != "up_to_date" {
		t.Fatalf("повтор: %+v %v", r, err)
	}
	// stop в канале (даже с одной подписью) — отказ
	stop := &memChan{name: "oob", raw: tk.doc(t, false, nil, []string{"workload.restart"}, now, time.Hour, "a")}
	if _, err := Renew(ctx, now.Add(2*time.Hour), cfg, tk.signers["r1"], tk.ring, []ChannelIO{cm, stop}, memSigs{}, ParseOptions{}); err == nil {
		t.Error("renew при stop")
	}
	// канал не читается — отказ
	if _, err := Renew(ctx, now.Add(2*time.Hour), cfg, tk.signers["r1"], tk.ring, []ChannelIO{cm, &memChan{name: "oob", err: &s3.Error{Kind: "timeout"}}}, memSigs{}, ParseOptions{}); err == nil {
		t.Error("renew при нечитаемом канале")
	}
	// ключ oncall — отказ
	if _, err := Renew(ctx, now.Add(2*time.Hour), cfg, tk.signers["a"], tk.ring, chans, memSigs{}, ParseOptions{}); err == nil {
		t.Error("oncall как renewer")
	}
	// у коллеги другой ttl — не сходится
	other := RenewConfig{Slot: time.Hour, TTL: 5 * time.Hour, Prefix: "renew/"}
	bad := memSigs{}
	if _, err := Renew(ctx, now.Add(3*time.Hour), other, tk.signers["r2"], tk.ring, chans, bad, ParseOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Renew(ctx, now.Add(3*time.Hour), cfg, tk.signers["r1"], tk.ring, chans, bad, ParseOptions{}); err == nil || !strings.Contains(err.Error(), "не сходится") {
		t.Errorf("другой ttl: %v", err)
	}
	// release новее начала слота — up_to_date
	rel := &memChan{name: "configmap", raw: tk.doc(t, false, nil, nil, now.Add(5*time.Hour+45*time.Minute), time.Hour, "a", "b")}
	r, err = Renew(ctx, now.Add(5*time.Hour+50*time.Minute), cfg, tk.signers["r1"], tk.ring, []ChannelIO{rel}, memSigs{}, ParseOptions{})
	if err != nil || r.Action != "up_to_date" {
		t.Errorf("release новее слота: %+v %v", r, err)
	}
}

func TestConfigMapPublisher(t *testing.T) {
	var got struct {
		method, path, query, ct, auth string
		body                          []byte
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.query, got.ct, got.auth = r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		got.body, _ = io.ReadAll(r.Body)
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"document": "DOC"}})
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := t.TempDir()
	ca := filepath.Join(d, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	os.WriteFile(filepath.Join(d, "tok"), []byte("tok\n"), 0o600)
	hc, _ := s3.NewHTTPClient(ca, 2*time.Second)
	p := ConfigMapPublisher{Client: hc, APIURL: srv.URL, Namespace: "aegisops-control", ConfigMapName: "kill-switch", TokenFile: filepath.Join(d, "tok")}
	if err := p.Publish(context.Background(), []byte(`{"x":"й"}`)); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Data     map[string]string `json:"data"`
		Metadata map[string]string `json:"metadata"`
	}
	json.Unmarshal(got.body, &body)
	if got.method != "PATCH" || got.path != "/api/v1/namespaces/aegisops-control/configmaps/kill-switch" || got.query != "fieldManager=aegis-killswitch&force=true" ||
		got.ct != "application/apply-patch+yaml" || got.auth != "Bearer tok" || body.Data["document"] != `{"x":"й"}` || body.Metadata["name"] != "kill-switch" {
		t.Errorf("запрос: %+v тело %s", got, got.body)
	}
	b, err := p.Read(context.Background())
	if err != nil || string(b) != "DOC" || got.method != "GET" {
		t.Errorf("Read: %q %v", b, err)
	}
}

type forbiddenSigs struct{ memSigs }

func (f forbiddenSigs) Get(ctx context.Context, k string) ([]byte, error) {
	if b, err := f.memSigs.Get(ctx, k); err == nil {
		return b, nil
	}
	return nil, &s3.Error{Kind: "http_403"}
}

// 403 на несуществующий ключ (нет ListBucket) — подписи пира пока нет, а не отказ.
func TestRenewForbiddenMeansNoPeerYet(t *testing.T) {
	tk := newTKeys(t)
	now := time.Date(2026, 11, 8, 10, 20, 0, 0, time.UTC)
	cm := &memChan{name: "configmap", raw: tk.doc(t, false, nil, nil, now.Add(-3*time.Hour), 6*time.Hour, "a", "b")}
	r, err := Renew(context.Background(), now, RenewConfig{Slot: time.Hour, TTL: 6 * time.Hour, Prefix: "renew/"}, tk.signers["r1"], tk.ring,
		[]ChannelIO{cm}, forbiddenSigs{memSigs{}}, ParseOptions{})
	if err != nil || r.Action != "waiting_peer" {
		t.Fatalf("%+v %v", r, err)
	}
}

// Пустой канал (no_document, 404) не мешает продлению; неразобранный ответ (decode) — отказ.
func TestRenewEmptyVsGarbledChannel(t *testing.T) {
	tk := newTKeys(t)
	now := time.Date(2026, 11, 8, 10, 20, 0, 0, time.UTC)
	cfg := RenewConfig{Slot: time.Hour, TTL: 6 * time.Hour, Prefix: "renew/"}
	oob := &memChan{name: "oob", raw: tk.doc(t, false, nil, nil, now.Add(-3*time.Hour), 6*time.Hour, "a", "b")}
	for _, kind := range []string{"no_document", "http_404"} {
		_, err := Renew(context.Background(), now, cfg, tk.signers["r1"], tk.ring,
			[]ChannelIO{&memChan{name: "configmap", err: &s3.Error{Kind: kind}}, oob}, memSigs{}, ParseOptions{})
		if err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
	if _, err := Renew(context.Background(), now, cfg, tk.signers["r1"], tk.ring,
		[]ChannelIO{&memChan{name: "configmap", err: &s3.Error{Kind: "decode"}}, oob}, memSigs{}, ParseOptions{}); err == nil {
		t.Error("неразобранный канал принят")
	}
}
