package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/bundle/bundletest"
)

// replay без -prepare-only тоже проверяет bundle: required=true и отсутствующий bundle — код 2 до записи и вызова модели;
// -prepare-only (без записи и сети) bundle не проверяет.
func TestReplayPolicyBundleRequired(t *testing.T) {
	s := newStack(t)
	{ // инициализация роутера
		var o, e bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		run(ctx, []string{"serve", "-config", s.cfgPath}, s.env(&o, &e))
		cancel()
	}
	_, keys := bundletest.Write(t, t.TempDir())
	s.setBundle(t, bundleSection(filepath.Join(t.TempDir(), "absent.json"), true, keys))
	before, posts := len(s.records(t)), s.tr.posts
	fx := filepath.Join(t.TempDir(), "fx.json")
	os.WriteFile(fx, []byte(replayFixture), 0o600)
	var o, e bytes.Buffer
	if c := exitCode(run(context.Background(), []string{"replay", "-config", s.cfgPath, "-in", fx}, s.env(&o, &e))); c != 2 {
		t.Fatalf("replay с required=true и без bundle: код %d, ожидался 2\n%s", c, e.String())
	}
	if len(s.records(t)) != before || s.tr.posts != posts {
		t.Error("при отказе проверки bundle replay записал или вызвал модель")
	}
	o.Reset()
	if err := run(context.Background(), []string{"replay", "-config", s.cfgPath, "-in", fx, "-prepare-only"}, s.env(&o, &e)); err != nil {
		t.Errorf("prepare-only не должен проверять bundle: %v", err)
	}
}
