package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/bundle"
	"github.com/limpjungle/aegis3311/internal/bundle/bundletest"
)

// setBundle записывает секцию policy_bundle в конфигурацию стека (nil — удаляет секцию).
func (s *stack) setBundle(t *testing.T, section map[string]any) {
	t.Helper()
	if section == nil {
		delete(s.cfg, "policy_bundle")
	} else {
		s.cfg["policy_bundle"] = section
	}
	b, err := json.Marshal(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func bundleSection(path string, required bool, keys []bundle.KeySpec) map[string]any {
	var ks []map[string]any
	for _, k := range keys {
		ks = append(ks, map[string]any{"path": k.Path, "issuer": k.Issuer})
	}
	return map[string]any{"path": path, "required": required, "keys": ks}
}

// serveFails запускает serve и ждёт отказ до приёма инцидентов: возвращает код и журнал.
func (s *stack) serveFails(t *testing.T) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := run(ctx, []string{"serve", "-config", s.cfgPath}, s.env(&out, &errb))
	if err == nil || ctx.Err() != nil {
		t.Fatalf("serve должен был отказать, err=%v\n%s", err, errb.String())
	}
	return exitCode(err), err.Error() + "\n" + errb.String()
}

// serveStarts запускает serve, ждёт события kill switch (старт состоялся), останавливает и возвращает журнал.
func (s *stack) serveStarts(t *testing.T) string {
	t.Helper()
	amGone.Store(true)
	r := s.start(t, nil)
	waitFor(t, "запуск intake", 10*time.Second, func() bool { return len(s.killSwitchEvents(t)) > 0 })
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v\n%s", err, r.errb.String())
	}
	return r.errb.String()
}

func TestServePolicyBundleSectionMissing(t *testing.T) {
	s := newStack(t)
	log := s.serveStarts(t)
	if !strings.Contains(log, "policy_bundle_missing") || !strings.Contains(log, "stage-0a-status") {
		t.Errorf("нет предупреждения policy_bundle_missing:\n%s", log)
	}
	if strings.Contains(log, "policy_bundle_verified") {
		t.Errorf("проверка не должна была выполняться:\n%s", log)
	}
}

func TestServePolicyBundleOptional(t *testing.T) {
	dir := t.TempDir()
	good, keys := bundletest.Write(t, dir)
	// Содержимое чужое: валидная подпись, но файл в манифесте не совпадает со встроенным.
	s0, spec0 := bundletest.Key(t, dir, "other")
	m := bundletest.Manifest(t)
	m.Files = append([]bundle.File(nil), m.Files...)
	m.Files[0].SHA256 = strings.Repeat("0", 64)
	foreign, _ := bundle.Sign(m, s0, bundletest.Issuer)
	foreignPath := filepath.Join(dir, "foreign.json")
	os.WriteFile(foreignPath, bundle.Marshal(foreign), 0o600)
	raw, _ := os.ReadFile(good)
	badSig := filepath.Join(dir, "bad.json")
	os.WriteFile(badSig, bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":2`), 1), 0o600)

	cases := map[string]map[string]any{
		"нет файла":         bundleSection(filepath.Join(dir, "absent.json"), false, keys),
		"подделанный":       bundleSection(badSig, false, keys),
		"чужое содержимое":  bundleSection(foreignPath, false, []bundle.KeySpec{spec0}),
		"неизвестный ключ":  bundleSection(good, false, []bundle.KeySpec{spec0}),
		"ключи не читаются": bundleSection(good, false, []bundle.KeySpec{{Path: filepath.Join(dir, "no.pub"), Issuer: "ci/x"}}),
	}
	for name, section := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStack(t)
			s.setBundle(t, section)
			log := s.serveStarts(t)
			if !strings.Contains(log, "policy_bundle_unverified") || strings.Contains(log, "policy_bundle_verified") {
				t.Errorf("ожидалось предупреждение policy_bundle_unverified:\n%s", log)
			}
		})
	}
}

// RT-11 в автотестах: required=true и любой изъян bundle — код 2 до приёма инцидентов.
func TestServePolicyBundleRequiredRefuses(t *testing.T) {
	dir := t.TempDir()
	good, keys := bundletest.Write(t, dir)
	signer := bundletest.Signer(t, dir, "policy-ci")

	oneApproval := bundletest.Manifest(t)
	oneApproval.Approvals.Approvers = oneApproval.Approvals.Approvers[:1]
	foreign := bundletest.Manifest(t)
	foreign.Files = append([]bundle.File(nil), foreign.Files...)
	foreign.Files[0].SHA256 = strings.Repeat("0", 64)
	write := func(name string, m bundle.Manifest) string {
		signed, err := bundle.Sign(m, signer, bundletest.Issuer)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		os.WriteFile(p, bundle.Marshal(signed), 0o600)
		return p
	}
	selfApproved := bundletest.Manifest(t)
	selfApproved.Approvals.Approvers[0].Login = selfApproved.Approvals.Author
	garbage := filepath.Join(dir, "garbage.json")
	os.WriteFile(garbage, []byte("{"), 0o600)

	cases := map[string]string{
		"нет файла":          filepath.Join(dir, "absent.json"),
		"одно одобрение":     write("one.json", oneApproval),
		"одобривший — автор": write("self.json", selfApproved),
		"чужое содержимое":   write("foreign.json", foreign),
		"мусор":              garbage,
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			s := newStack(t)
			s.setBundle(t, bundleSection(path, true, keys))
			code, log := s.serveFails(t)
			if code != 2 {
				t.Errorf("код %d, ожидался 2:\n%s", code, log)
			}
			if len(s.killSwitchEvents(t)) != 0 || len(s.records(t)) != 0 {
				t.Error("до отказа не должно быть событий и записей")
			}
		})
	}
	t.Run("неизвестный ключ", func(t *testing.T) {
		s := newStack(t)
		_, other := bundletest.Key(t, dir, "stranger")
		s.setBundle(t, bundleSection(good, true, []bundle.KeySpec{other}))
		if code, log := s.serveFails(t); code != 2 {
			t.Errorf("код %d:\n%s", code, log)
		}
	})
}

// Ключ аудита или kill switch в keyring bundle — ошибка конфигурации при любом required.
func TestServePolicyBundleKeyOverlap(t *testing.T) {
	dir := t.TempDir()
	good, _ := bundletest.Write(t, dir)
	for _, required := range []bool{false, true} {
		for name, pubOf := range map[string]func(s *stack) string{
			"ключ аудита": func(s *stack) string { return filepath.Join(filepath.Dir(s.cfgPath), "audit.pub") },
			"ключ kill switch": func(s *stack) string {
				return s.cfg["kill_switch"].(map[string]any)["keys"].([]any)[0].(map[string]any)["path"].(string)
			},
		} {
			t.Run(name+map[bool]string{false: "/required=false", true: "/required=true"}[required], func(t *testing.T) {
				s := newStack(t)
				// Файл ключа другой (копия), чтобы пересечение ловилось по содержимому, а не по пути.
				src, err := os.ReadFile(pubOf(s))
				if err != nil {
					t.Fatal(err)
				}
				cp := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".pub")
				os.WriteFile(cp, src, 0o644)
				s.setBundle(t, bundleSection(good, required, []bundle.KeySpec{{Path: cp, Issuer: "ci/policy-signing"}}))
				code, log := s.serveFails(t)
				if code != 2 || !strings.Contains(log, "policy bundle") {
					t.Errorf("код %d:\n%s", code, log)
				}
			})
		}
	}
}

func TestServePolicyBundleRequiredValid(t *testing.T) {
	s := newStack(t)
	path, keys := bundletest.Write(t, t.TempDir())
	s.setBundle(t, bundleSection(path, true, keys))
	log := s.serveStarts(t)
	for _, want := range []string{"policy_bundle_verified", `"sequence":1`, bundletest.Commit, "policy_bundle_digest", "catalog_digest", "llm_assets_digest", `"pr":7`} {
		if !strings.Contains(log, want) {
			t.Errorf("в журнале нет %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "policy_bundle_unverified") || strings.Contains(log, "policy_bundle_missing") {
		t.Errorf("лишние предупреждения:\n%s", log)
	}
}
