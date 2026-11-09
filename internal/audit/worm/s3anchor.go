// Package worm — хранилище checkpoint'ов аудита в bucket'е S3 с Object Lock (режим COMPLIANCE). Сетевой код вынесен из
// ядра audit. Checkpoint'ы читаются по всем версиям объекта: подделку можно дописать лишь новой версией, старую удалить
// нельзя, а audit.Verify требует совпадения всех checkpoint'ов на одном seq.
package worm

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// ErrDeleteMarker — на ключе checkpoint'а есть delete marker: удаление в WORM-хранилище недопустимо.
var ErrDeleteMarker = errors.New("worm: на ключе checkpoint'а delete marker")

var (
	prefixRe  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*/)*$`)
	chainIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`) // как chainRe audit
	seqRe     = regexp.MustCompile(`^[0-9]{20}$`)
)

// Config — расположение bucket'а и срок хранения. Ключи доступа — отдельно (s3.CredFiles).
type Config struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"` // "" или "a/b/" (без ведущего "/" и ".."), завершается "/"
	CAFile    string `json:"ca_file"`
	PathStyle bool   `json:"path_style"`
	Retention string `json:"retention"` // time.ParseDuration, обязателен, > 0, например "8760h"
	Timeout   string `json:"timeout"`   // например "10s"; пусто — 10s
}

// Validate проверяет конфигурацию без обращения к сети.
func (c Config) Validate() error {
	if c.Endpoint == "" || c.Region == "" || c.Bucket == "" {
		return errors.New("worm: нужны endpoint, region и bucket")
	}
	if !prefixRe.MatchString(c.Prefix) || strings.Contains(c.Prefix, "..") {
		return fmt.Errorf("worm: некорректный prefix %q", c.Prefix)
	}
	if d, err := time.ParseDuration(c.Retention); err != nil || d <= 0 {
		return errors.New("worm: retention обязателен: положительная длительность, например \"8760h\"")
	}
	if c.Timeout != "" {
		if d, err := time.ParseDuration(c.Timeout); err != nil || d <= 0 {
			return errors.New("worm: timeout: ожидается положительная длительность, например \"10s\"")
		}
	}
	return nil
}

// S3Anchor — audit.CheckpointStore поверх S3 с Object Lock.
type S3Anchor struct {
	C         *s3.Client
	Prefix    string
	Retention time.Duration
	Timeout   time.Duration
	Now       func() time.Time
}

var _ audit.CheckpointStore = (*S3Anchor)(nil)

// New создаёт S3Anchor; now == nil → time.Now.
func New(cfg Config, creds s3.CredFiles, now func() time.Time) (*S3Anchor, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	ret, _ := time.ParseDuration(cfg.Retention)
	to := 10 * time.Second
	if cfg.Timeout != "" {
		to, _ = time.ParseDuration(cfg.Timeout)
	}
	hc, err := s3.NewHTTPClient(cfg.CAFile, to)
	if err != nil {
		return nil, err
	}
	c := &s3.Client{Cfg: s3.Config{Endpoint: cfg.Endpoint, Region: cfg.Region, Bucket: cfg.Bucket, CAFile: cfg.CAFile, PathStyle: cfg.PathStyle},
		Creds: creds, HTTP: hc, Now: now}
	return &S3Anchor{C: c, Prefix: cfg.Prefix, Retention: ret, Timeout: to, Now: now}, nil
}

func (a *S3Anchor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *S3Anchor) ctx() (context.Context, context.CancelFunc) {
	to := a.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	return context.WithTimeout(context.Background(), to)
}

func (a *S3Anchor) dir(chainID string) (string, error) {
	if !chainIDRe.MatchString(chainID) {
		return "", fmt.Errorf("worm: некорректный chain_id %q", chainID)
	}
	if !prefixRe.MatchString(a.Prefix) || strings.Contains(a.Prefix, "..") {
		return "", fmt.Errorf("worm: некорректный prefix %q", a.Prefix)
	}
	return a.Prefix + chainID + "/cp/", nil
}

// Put сохраняет checkpoint под ключом <prefix><chain_id>/cp/<seq>.json с блокировкой COMPLIANCE до now+Retention.
// Повтор того же seq создаёт новую версию (допустимо: Verify требует совпадения всех версий).
func (a *S3Anchor) Put(c audit.Checkpoint) error {
	dir, err := a.dir(c.ChainID)
	if err != nil {
		return err
	}
	if a.Retention <= 0 {
		return errors.New("worm: retention обязателен")
	}
	b, err := jsonLine(c)
	if err != nil {
		return err
	}
	sum := md5.Sum(b)
	h := http.Header{}
	h.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	h.Set("x-amz-object-lock-mode", "COMPLIANCE")
	h.Set("x-amz-object-lock-retain-until-date", a.now().UTC().Add(a.Retention).Format(time.RFC3339))
	ctx, cancel := a.ctx()
	defer cancel()
	return a.C.PutObject(ctx, dir+fmt.Sprintf("%020d", c.Seq)+".json", b, "application/json", h)
}

// LoadCheckpoints читает все версии всех checkpoint'ов цепочки (подпись не проверяется: это делает Verify).
func (a *S3Anchor) LoadCheckpoints(chainID string) ([]audit.Checkpoint, error) {
	return a.load(chainID, false)
}

// LatestCheckpoints читает все версии checkpoint'а с максимальным seq; пусто — checkpoint'ов нет (новая цепочка).
func (a *S3Anchor) LatestCheckpoints(chainID string) ([]audit.Checkpoint, error) {
	return a.load(chainID, true)
}

func (a *S3Anchor) load(chainID string, latestOnly bool) ([]audit.Checkpoint, error) {
	dir, err := a.dir(chainID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := a.ctx()
	defer cancel()
	vs, err := a.C.ListVersions(ctx, dir)
	if err != nil {
		return nil, err
	}
	seqs := make([]uint64, len(vs))
	var top uint64
	for i, v := range vs {
		rest, ok := strings.CutPrefix(v.Key, dir)
		num, ok2 := strings.CutSuffix(rest, ".json")
		if !ok || !ok2 || !seqRe.MatchString(num) {
			return nil, fmt.Errorf("worm: ключ вне шаблона checkpoint'ов: %q", v.Key)
		}
		if v.DeleteMarker {
			return nil, fmt.Errorf("%w: %s", ErrDeleteMarker, v.Key)
		}
		if seqs[i], err = strconv.ParseUint(num, 10, 64); err != nil {
			return nil, fmt.Errorf("worm: ключ вне шаблона checkpoint'ов: %q", v.Key)
		}
		top = max(top, seqs[i])
	}
	var out []audit.Checkpoint
	for i, v := range vs {
		if latestOnly && seqs[i] != top {
			continue
		}
		b, _, err := a.C.GetVersion(ctx, v.Key, v.VersionID)
		if err != nil {
			return nil, err
		}
		var c audit.Checkpoint
		if err := strictjson.Decode(b, &c); err != nil {
			return nil, fmt.Errorf("worm: %s: %w", v.Key, err)
		}
		if c.ChainID != chainID || c.Seq != seqs[i] {
			return nil, fmt.Errorf("worm: %s: chain_id или seq checkpoint'а не совпадают с ключом", v.Key)
		}
		out = append(out, c)
	}
	return out, nil
}

func jsonLine(c audit.Checkpoint) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
