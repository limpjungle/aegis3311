// Команда aegis-killswitch: управление kill switch (architecture.md §2.2) — остановка, снятие двумя дежурными,
// публикация в оба канала, продление подтверждения и проверка состояния. Нужна для учения G0 и эксплуатации.
//
//	aegis-killswitch stop    -config FILE -key KEY.pem [-global] [-cluster C]... [-action A]... [-ttl 24h] [-channels configmap,oob] [-out FILE]
//	aegis-killswitch release -config FILE -key KEY.pem [-ttl 6h] -out FILE
//	aegis-killswitch cosign  -config FILE -key KEY.pem -in FILE [-out FILE] [-publish] [-channels configmap,oob]
//	aegis-killswitch publish -config FILE -in FILE [-channels configmap,oob]
//	aegis-killswitch renew   -config FILE -key KEY.pem [-channels configmap,oob]
//	aegis-killswitch status  -config FILE [-cluster C] [-channels configmap,oob]
//
// stop подписывает документ одним ключом и публикует его (с -out — только файл, без сети: запасной путь). release
// готовит документ «не остановлен» с первой подписью и ничего не публикует: файл передаётся второму дежурному,
// который подписывает его cosign -publish. Снять остановку и подтвердить работу можно только двумя подписями разных
// ключей oncall. renew — ежечасное продление двумя независимыми ключами renewer; при действующем stop отказывает.
// После публикации документ читается обратно из каждого канала. status печатает оценку (водяные знаки — только из каналов).
//
// issuer подписи берётся из ключей конфигурации по key_id приватного ключа. Секреты — только из файлов:
// AEGIS_KILLSWITCH_KUBE_TOKEN_FILE (запись в ConfigMap), AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE,
// AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE и необязательный AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE (ключи с правами записи).
//
// Коды выхода: 0 — успех (в том числе renew: waiting_peer и up_to_date); 1 — сбой публикации или проверки любого канала,
// отказ release/publish/renew/cosign, порог подписей не выполнен; 2 — ошибка аргументов, конфигурации или ключей.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const maxConfigBytes = 1 << 20

// maxSkew — допуск опережения issued_at при проверках CLI (как max_skew intake по умолчанию).
const maxSkew = 2 * time.Minute

// Config — конфигурация CLI (JSON, строгий разбор), без секретов.
type Config struct {
	Keys      []killswitch.KeySpec `json:"keys"`
	ConfigMap struct {
		APIURL    string `json:"api_url"`
		CAFile    string `json:"ca_file"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"configmap"`
	OOB   s3.Config `json:"oob"`
	Renew struct {
		Slot   string `json:"slot"`
		TTL    string `json:"ttl"`
		Prefix string `json:"prefix"`
	} `json:"renew"`
	Timeout string `json:"timeout"`
}

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

func usage(err error) error    { return exitError{2, err} }
func rejected(err error) error { return exitError{1, err} }

type env struct {
	getenv func(string) string
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time
	// doer создаёт HTTP-транспорт по CA-файлу; nil — s3.NewHTTPClient.
	doer func(caFile string, timeout time.Duration) (s3.Doer, error)
}

func main() {
	e := env{getenv: os.Getenv, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	if err := run(context.Background(), os.Args[1:], e); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-killswitch:", err)
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(2)
	}
}

type multi []string

func (m *multi) String() string     { return fmt.Sprint(*m) }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("конфигурация: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(b) > maxConfigBytes {
		return Config{}, errors.New("конфигурация: не читается или больше 1 MiB")
	}
	var c Config
	if err := strictjson.Decode(b, &c); err != nil {
		return Config{}, fmt.Errorf("конфигурация: %w", err)
	}
	for _, d := range []struct {
		p *string
		v string
	}{{&c.ConfigMap.Namespace, "aegisops-control"}, {&c.ConfigMap.Name, "kill-switch"}, {&c.Renew.Slot, "1h"}, {&c.Renew.TTL, "6h"},
		{&c.Renew.Prefix, "renew/"}, {&c.Timeout, "10s"}} {
		if *d.p == "" {
			*d.p = d.v
		}
	}
	return c, nil
}

func (c Config) timeout() (time.Duration, error) {
	d, err := time.ParseDuration(c.Timeout)
	if err != nil || d <= 0 || d > 5*time.Minute {
		return 0, errors.New("конфигурация: timeout: от 1ns до 5m, например \"10s\"")
	}
	return d, nil
}

// timed ограничивает каждое обращение к каналу таймаутом конфигурации.
type timed struct {
	killswitch.ChannelIO
	d time.Duration
}

func (t timed) Read(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, t.d)
	defer cancel()
	return t.ChannelIO.Read(ctx)
}

func (t timed) Publish(ctx context.Context, doc []byte) error {
	ctx, cancel := context.WithTimeout(ctx, t.d)
	defer cancel()
	return t.ChannelIO.Publish(ctx, doc)
}

type sigStore struct {
	c *s3.Client
	d time.Duration
}

func (s sigStore) Put(ctx context.Context, key string, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, s.d)
	defer cancel()
	return s.c.Put(ctx, key, b, "application/json")
}

func (s sigStore) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.d)
	defer cancel()
	return s.c.Get(ctx, key)
}

// session — всё, что нужно команде: конфигурация, ключи и каналы.
type session struct {
	cfg  Config
	keys killswitch.Keyring
	e    env
	d    time.Duration
	s3c  *s3.Client
	opts killswitch.ParseOptions
}

func (e env) http(ca string, d time.Duration) (s3.Doer, error) {
	if e.doer != nil {
		return e.doer(ca, d)
	}
	return s3.NewHTTPClient(ca, d)
}

func newSession(cfgPath string, e env) (*session, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, usage(err)
	}
	d, err := cfg.timeout()
	if err != nil {
		return nil, usage(err)
	}
	keys, err := killswitch.LoadKeyring(cfg.Keys)
	if err != nil {
		return nil, usage(err)
	}
	cat := catalog.MustLoadEmbedded()
	return &session{cfg: cfg, keys: keys, e: e, d: d,
		opts: killswitch.ParseOptions{KnownAction: func(a string) bool { _, ok := cat.Get(a); return ok }}}, nil
}

// s3Client создаёт клиент внешнего канала (ключи доступа из файлов; читаемость проверяется сразу).
func (s *session) s3Client() (*s3.Client, error) {
	if s.s3c != nil {
		return s.s3c, nil
	}
	creds := s3.CredFiles{AccessKeyIDFile: s.e.getenv("AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE"),
		SecretKeyFile: s.e.getenv("AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE"), SessionTokenFile: s.e.getenv("AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE")}
	if _, err := creds.Load(); err != nil {
		return nil, usage(err)
	}
	hc, err := s.e.http(s.cfg.OOB.CAFile, s.d)
	if err != nil {
		return nil, usage(err)
	}
	s.s3c = &s3.Client{Cfg: s.cfg.OOB, Creds: creds, HTTP: hc, Now: s.e.now, MaxBytes: killswitch.MaxDocBytes}
	return s.s3c, nil
}

// channels строит каналы по списку имён через запятую (пусто — оба).
func (s *session) channels(list string) ([]killswitch.ChannelIO, error) {
	names := []string{"configmap", "oob"}
	if list != "" {
		names = strings.Split(list, ",")
	}
	var out []killswitch.ChannelIO
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			return nil, usage(fmt.Errorf("-channels: канал %q повторяется", n))
		}
		seen[n] = true
		switch n {
		case "configmap":
			c := s.cfg.ConfigMap
			if c.APIURL == "" {
				return nil, usage(errors.New("конфигурация: configmap.api_url не задан"))
			}
			tf := s.e.getenv("AEGIS_KILLSWITCH_KUBE_TOKEN_FILE")
			if tf == "" {
				return nil, usage(errors.New("не задан AEGIS_KILLSWITCH_KUBE_TOKEN_FILE"))
			}
			hc, err := s.e.http(c.CAFile, s.d)
			if err != nil {
				return nil, usage(err)
			}
			out = append(out, timed{killswitch.ConfigMapPublisher{Client: hc, APIURL: c.APIURL, Namespace: c.Namespace, ConfigMapName: c.Name, TokenFile: tf}, s.d})
		case "oob":
			c, err := s.s3Client()
			if err != nil {
				return nil, err
			}
			out = append(out, timed{killswitch.S3Publisher{C: c}, s.d})
		default:
			return nil, usage(fmt.Errorf("-channels: неизвестный канал %q (configmap | oob)", n))
		}
	}
	return out, nil
}

// signer загружает приватный ключ и находит его в ключах конфигурации: issuer берётся оттуда.
func (s *session) signer(path string) (*audit.Ed25519Signer, killswitch.Key, error) {
	sg, err := audit.LoadPrivateKey(path)
	if err != nil {
		return nil, killswitch.Key{}, usage(err)
	}
	k, ok := s.keys[sg.KeyID()]
	if !ok {
		return nil, killswitch.Key{}, usage(fmt.Errorf("ключ %s отсутствует в keys конфигурации", sg.KeyID()))
	}
	return sg, k, nil
}

func stamp(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

type flags struct {
	cfgPath, key, in, out, ttl, chans string
	global, publish                   bool
	clusters, actions                 multi
}

func run(ctx context.Context, args []string, e env) error {
	const cmds = "команда: stop | release | cosign | publish | renew | status"
	if len(args) == 0 {
		return usage(errors.New(cmds))
	}
	cmd := args[0]
	switch cmd {
	case "stop", "release", "cosign", "publish", "renew", "status":
	default:
		return usage(fmt.Errorf("неизвестная команда %q; %s", cmd, cmds))
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f flags
	fs.StringVar(&f.cfgPath, "config", "", "файл конфигурации (JSON)")
	fs.StringVar(&f.key, "key", "", "приватный ключ подписи (PEM PKCS#8)")
	fs.StringVar(&f.in, "in", "", "входной документ")
	fs.StringVar(&f.out, "out", "", "выходной файл документа")
	fs.StringVar(&f.ttl, "ttl", "", "TTL документа")
	fs.StringVar(&f.chans, "channels", "", "каналы через запятую: configmap,oob (по умолчанию оба)")
	fs.BoolVar(&f.global, "global", false, "stop: остановить все цели")
	fs.BoolVar(&f.publish, "publish", false, "cosign: опубликовать при выполнении порога")
	fs.Var(&f.clusters, "cluster", "stop: кластер для остановки (повторяется); status: кластер intake")
	fs.Var(&f.actions, "action", "stop: тип действия для запрета (повторяется)")
	if err := fs.Parse(args[1:]); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("лишние аргументы: %v", fs.Args()))
	}
	if f.cfgPath == "" {
		return usage(fmt.Errorf("%s: нужен -config", cmd))
	}
	need := map[string][][2]string{
		"stop":    {{"-key", f.key}},
		"release": {{"-key", f.key}, {"-out", f.out}},
		"cosign":  {{"-key", f.key}, {"-in", f.in}},
		"publish": {{"-in", f.in}},
		"renew":   {{"-key", f.key}},
	}
	for _, n := range need[cmd] {
		if n[1] == "" {
			return usage(fmt.Errorf("%s: нужен %s", cmd, n[0]))
		}
	}
	if cmd != "stop" && (f.global || len(f.actions) > 0 || (cmd != "status" && len(f.clusters) > 0)) {
		return usage(fmt.Errorf("%s: -global, -action и -cluster относятся к stop (и -cluster к status)", cmd))
	}
	s, err := newSession(f.cfgPath, e)
	if err != nil {
		return err
	}
	switch cmd {
	case "stop":
		return s.stop(ctx, f)
	case "release":
		return s.release(f)
	case "cosign":
		return s.cosign(ctx, f)
	case "publish":
		return s.publish(ctx, f)
	case "renew":
		return s.renew(ctx, f)
	}
	if len(f.clusters) > 1 {
		return usage(errors.New("status: один -cluster"))
	}
	cl := ""
	if len(f.clusters) == 1 {
		cl = f.clusters[0]
	}
	return s.status(ctx, cl, f.chans)
}

func parseTTL(v, def string) (time.Duration, error) {
	if v == "" {
		v = def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, usage(fmt.Errorf("-ttl: %v", err))
	}
	return d, nil
}

// newDoc создаёт документ, подписывает его и проверяет тем же Parse, что и intake.
func (s *session) newDoc(sg *audit.Ed25519Signer, k killswitch.Key, global bool, clusters, actions []string, ttl time.Duration) (killswitch.Document, error) {
	cl, ac := append([]string{}, clusters...), append([]string{}, actions...)
	sort.Strings(cl)
	sort.Strings(ac)
	d := killswitch.Document{Schema: killswitch.DocSchema, Global: global, Clusters: cl, Actions: ac,
		IssuedAt: stamp(s.e.now()), TTL: ttl.String(), Issuer: k.Issuer, Signatures: []killswitch.Signature{}}
	sig, err := killswitch.SignatureFor(d, sg, k.Issuer)
	if err != nil {
		return d, usage(err)
	}
	if d, err = killswitch.AddSignature(d, sig); err != nil {
		return d, usage(err)
	}
	if _, err := killswitch.Parse(killswitch.Marshal(d), s.keys, s.opts); err != nil {
		return d, usage(err)
	}
	return d, nil
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return usage(err)
	}
	if err := os.WriteFile(path, append(append([]byte{}, b...), '\n'), 0o644); err != nil {
		return usage(err)
	}
	return nil
}

func (s *session) stop(ctx context.Context, f flags) error {
	if !f.global && len(f.clusters) == 0 && len(f.actions) == 0 {
		return usage(errors.New("stop: нужен хотя бы один из -global, -cluster, -action"))
	}
	ttl, err := parseTTL(f.ttl, "24h")
	if err != nil {
		return err
	}
	sg, k, err := s.signer(f.key)
	if err != nil {
		return err
	}
	d, err := s.newDoc(sg, k, f.global, f.clusters, f.actions, ttl)
	if err != nil {
		return err
	}
	raw := killswitch.Marshal(d)
	if f.out != "" { // офлайн: файл для запасного пути (kubectl apply, консоль хранилища)
		if err := writeFile(f.out, raw); err != nil {
			return err
		}
		return s.printDoc(raw)
	}
	cs, err := s.channels(f.chans)
	if err != nil {
		return err
	}
	return s.publishAll(ctx, raw, cs)
}

func (s *session) printDoc(raw []byte) error {
	v, err := killswitch.Parse(raw, s.keys, s.opts)
	if err != nil {
		return rejected(err)
	}
	return printJSON(s.e.stdout, map[string]any{"doc_sha256": v.SHA256, "content_sha256": v.ContentSHA256, "issued_at": audit.Timestamp(v.IssuedAt),
		"signers": v.SignerIssuers()})
}

func (s *session) release(f flags) error {
	ttl, err := parseTTL(f.ttl, "6h")
	if err != nil {
		return err
	}
	sg, k, err := s.signer(f.key)
	if err != nil {
		return err
	}
	if k.Role != killswitch.RoleOncall {
		return usage(errors.New("release: ключ должен быть роли oncall"))
	}
	d, err := s.newDoc(sg, k, false, nil, nil, ttl)
	if err != nil {
		return err
	}
	raw := killswitch.Marshal(d)
	if err := writeFile(f.out, raw); err != nil {
		return err
	}
	fmt.Fprintln(s.e.stderr, "документ подписан одним ключом и не опубликован: передайте файл второму дежурному (aegis-killswitch cosign -publish)")
	return s.printDoc(raw)
}

func isRun(v killswitch.Verified) bool {
	return !v.Doc.Global && len(v.Doc.Clusters) == 0 && len(v.Doc.Actions) == 0
}

func effect(v killswitch.Verified) string {
	switch {
	case v.Doc.Global:
		return "global"
	case len(v.Doc.Clusters) > 0:
		return "clusters " + strings.Join(v.Doc.Clusters, ",")
	case len(v.Doc.Actions) > 0:
		return "actions " + strings.Join(v.Doc.Actions, ",")
	}
	return "run (не остановлен)"
}

func (s *session) load(path string) (killswitch.Verified, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return killswitch.Verified{}, usage(err)
	}
	v, err := killswitch.Parse(bytes.TrimSpace(b), s.keys, s.opts)
	if err != nil {
		return v, rejected(err)
	}
	return v, nil
}

// fresh: документ свежий и чистый (не просрочен, не из будущего, не запятнан).
func (s *session) fresh(v killswitch.Verified) error {
	now := s.e.now()
	switch {
	case v.Tainted:
		return rejected(errors.New("документ запятнан: есть невалидные или незнакомые подписи; подтверждением он не считается"))
	case !now.Before(v.IssuedAt.Add(v.TTL)):
		return rejected(fmt.Errorf("документ просрочен (issued_at %s, ttl %s)", audit.Timestamp(v.IssuedAt), v.TTL))
	case v.IssuedAt.After(now.Add(maxSkew)):
		return rejected(fmt.Errorf("issued_at %s в будущем: проверьте часы", audit.Timestamp(v.IssuedAt)))
	}
	return nil
}

func (s *session) cosign(ctx context.Context, f flags) error {
	sg, k, err := s.signer(f.key)
	if err != nil {
		return err
	}
	v, err := s.load(f.in)
	if err != nil {
		return err
	}
	if err := s.fresh(v); err != nil {
		return err
	}
	for _, sig := range v.Doc.Signatures {
		if sig.KeyID == sg.KeyID() {
			return rejected(errors.New("cosign: этот ключ уже подписал документ; нужна подпись другого ключа"))
		}
	}
	if v.Doc.Global || len(v.Doc.Clusters) > 0 {
		return rejected(errors.New("cosign: документ с global или clusters второй подписью не подтверждается; публикуйте остановку через stop"))
	}
	if isRun(v) && k.Role != killswitch.RoleOncall {
		return rejected(errors.New("cosign: снимать остановку могут только ключи роли oncall"))
	}
	fmt.Fprintf(s.e.stderr, "эффект: %s\nissued_at: %s\nttl: %s\nподписанты: %s\ncontent_sha256: %s\n", effect(v), audit.Timestamp(v.IssuedAt), v.TTL,
		strings.Join(v.SignerIssuers(), ", "), v.ContentSHA256)
	sig, err := killswitch.SignatureFor(v.Doc, sg, k.Issuer)
	if err != nil {
		return usage(err)
	}
	nd, err := killswitch.AddSignature(v.Doc, sig)
	if err != nil {
		return rejected(err)
	}
	raw := killswitch.Marshal(nd)
	nv, err := killswitch.Parse(raw, s.keys, s.opts)
	if err != nil {
		return rejected(err)
	}
	if f.out != "" {
		if err := writeFile(f.out, raw); err != nil {
			return err
		}
	}
	if !f.publish {
		if f.out == "" {
			fmt.Fprintf(s.e.stdout, "%s\n", raw)
		}
		return nil
	}
	if err := thresholdMet(nv); err != nil {
		return err
	}
	cs, err := s.channels(f.chans)
	if err != nil {
		return err
	}
	if err := s.checkNewerThanStop(ctx, nv, cs); err != nil {
		return err
	}
	return s.publishAll(ctx, raw, cs)
}

// checkNewerThanStop: run не публикуется поверх более нового или равного stop (intake всё равно его не примет:
// водяной знак) и поверх канала, в котором stop исключить нельзя. Канал не прочитан или документ в нём не
// разбирается — отказ; пустой канал (S3 404, ConfigMap без document) — не препятствие.
func (s *session) checkNewerThanStop(ctx context.Context, v killswitch.Verified, cs []killswitch.ChannelIO) error {
	if !isRun(v) {
		return nil
	}
	for _, c := range cs {
		raw, err := c.Read(ctx)
		if k := errText(err); err != nil && k != "http_404" && k != "no_document" {
			return rejected(fmt.Errorf("канал %s не прочитан (%s): нельзя исключить более новый stop; повторите, когда канал доступен", c.Name(), k))
		}
		if err != nil || len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		cur, err := killswitch.Parse(raw, s.keys, s.opts)
		if err != nil {
			return rejected(fmt.Errorf("документ в канале %s не разбирается (%s): нельзя исключить более новый stop", c.Name(), errText(err)))
		}
		if !isRun(cur) && !v.IssuedAt.After(cur.IssuedAt) {
			return rejected(fmt.Errorf("в канале %s stop новее документа (issued_at %s): подготовьте новый release", c.Name(), audit.Timestamp(cur.IssuedAt)))
		}
	}
	return nil
}

// thresholdMet: stop публикуется от одной подписи, run — только с двумя подписями oncall.
func thresholdMet(v killswitch.Verified) error {
	if isRun(v) && v.Confirmation("") != "oncall" {
		return rejected(fmt.Errorf("порог не выполнен: подтверждение требует двух подписей разных ключей oncall (сейчас: %s)", v.Confirmation("")))
	}
	return nil
}

func (s *session) publish(ctx context.Context, f flags) error {
	v, err := s.load(f.in)
	if err != nil {
		return err
	}
	if err := s.fresh(v); err != nil {
		return err
	}
	if err := thresholdMet(v); err != nil {
		return err
	}
	cs, err := s.channels(f.chans)
	if err != nil {
		return err
	}
	if err := s.checkNewerThanStop(ctx, v, cs); err != nil {
		return err
	}
	return s.publishAll(ctx, killswitch.Marshal(v.Doc), cs)
}

type chanResult struct {
	Channel       string `json:"channel"`
	Published     bool   `json:"published"`
	ReadBackMatch bool   `json:"read_back_match"`
	Error         string `json:"error"`
}

// publishAll публикует документ в каналы, читает обратно и печатает итог. Любой сбой — код 1.
func (s *session) publishAll(ctx context.Context, raw []byte, cs []killswitch.ChannelIO) error {
	v, err := killswitch.Parse(raw, s.keys, s.opts)
	if err != nil {
		return rejected(err)
	}
	res := make([]chanResult, 0, len(cs))
	failed := false
	for _, c := range cs {
		r := chanResult{Channel: c.Name()}
		if err := c.Publish(ctx, raw); err != nil {
			r.Error = errText(err)
		} else {
			r.Published = true
			back, err := c.Read(ctx)
			switch {
			case err != nil:
				r.Error = "read_back: " + errText(err)
			default:
				r.ReadBackMatch = bytes.Equal(back, raw)
				if !r.ReadBackMatch {
					r.Error = "read_back_mismatch"
				}
			}
		}
		failed = failed || !r.Published || !r.ReadBackMatch
		res = append(res, r)
	}
	if err := printJSON(s.e.stdout, map[string]any{"doc_sha256": v.SHA256, "content_sha256": v.ContentSHA256,
		"issued_at": audit.Timestamp(v.IssuedAt), "signers": v.SignerIssuers(), "channels": res}); err != nil {
		return rejected(err)
	}
	if failed {
		return rejected(errors.New("публикация не удалась хотя бы в одном канале"))
	}
	return nil
}

// errText — класс ошибки без деталей транспорта.
func errText(err error) string {
	var k interface{ ErrKind() string }
	if errors.As(err, &k) {
		return k.ErrKind()
	}
	return "error"
}

func (s *session) renew(ctx context.Context, f flags) error {
	sg, _, err := s.signer(f.key)
	if err != nil {
		return err
	}
	slot, e1 := time.ParseDuration(s.cfg.Renew.Slot)
	ttl, e2 := time.ParseDuration(s.cfg.Renew.TTL)
	if e1 != nil || e2 != nil || slot < time.Minute {
		return usage(errors.New("конфигурация: renew.slot и renew.ttl — длительности (slot не меньше 1m)"))
	}
	cs, err := s.channels(f.chans)
	if err != nil {
		return err
	}
	c, err := s.s3Client() // подписи renewer'ов передаются через S3
	if err != nil {
		return err
	}
	res, err := killswitch.Renew(ctx, s.e.now(), killswitch.RenewConfig{Slot: slot, TTL: ttl, Prefix: s.cfg.Renew.Prefix}, sg, s.keys, cs, sigStore{c, s.d}, s.opts)
	if err != nil {
		return rejected(err)
	}
	return printJSON(s.e.stdout, res)
}

func (s *session) status(ctx context.Context, cluster, chans string) error {
	cs, err := s.channels(chans)
	if err != nil {
		return err
	}
	var views []killswitch.ChannelView
	for _, c := range cs {
		vw := killswitch.ChannelView{Channel: c.Name()}
		raw, err := c.Read(ctx)
		if err == nil {
			var v killswitch.Verified
			if v, err = killswitch.Parse(raw, s.keys, s.opts); err == nil {
				vw.Doc = &v
			} else {
				vw.Err = "invalid"
				var de *killswitch.DocError
				if errors.As(err, &de) {
					vw.Err = de.Class
				}
			}
		} else {
			vw.Err = errText(err)
		}
		views = append(views, vw)
	}
	st := killswitch.Evaluate(s.e.now(), views, killswitch.Marks{}, killswitch.Options{Cluster: cluster, MaxSkew: maxSkew})
	out := map[string]any{"state": st.Info(), "channels": st.Channels, "triggers": st.Triggers}
	if !st.ConfirmedUntil.IsZero() {
		out["confirmed_until"] = audit.Timestamp(st.ConfirmedUntil)
	}
	if cluster == "" {
		out["note"] = "кластер не задан (-cluster): остановка по clusters не оценивалась"
	}
	return printJSON(s.e.stdout, out)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
