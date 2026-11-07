package routersvc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretsMissingEach(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"OPENROUTER_API_KEY_FILE", "AEGIS_MASKER_KEY_FILE", AuditKeyEnv} {
		for _, empty := range []bool{false, true} {
			saved := f.env[name]
			if empty {
				f.env[name] = ""
			} else {
				delete(f.env, name)
			}
			_, err := LoadSecrets(f.getenv)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s (empty=%v): %v", name, empty, err)
			}
			f.env[name] = saved
		}
	}
	if _, err := LoadSecrets(f.getenv); err != nil {
		t.Fatal(err)
	}
}

func TestSecretsAuditKeyErrors(t *testing.T) {
	f := newFixture(t)
	// Мусор в ключе аудита: ни путь, ни содержимое в ошибку не попадают.
	junk := "ZZ" + runtimeSecret(t)
	p := filepath.Join(t.TempDir(), "junk-audit-key")
	must(t, os.WriteFile(p, []byte(junk), 0o600))
	f.env[AuditKeyEnv] = p
	_, err := LoadSecrets(f.getenv)
	if err == nil {
		t.Fatal("мусор принят")
	}
	for _, bad := range []string{junk, p, "junk-audit-key"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("ошибка содержит %q: %v", bad, err)
		}
	}
	if !strings.Contains(err.Error(), AuditKeyEnv) {
		t.Errorf("нет имени переменной: %v", err)
	}
	// Нет файла: errno без пути.
	missing := filepath.Join(t.TempDir(), "absent-key-file")
	f.env[AuditKeyEnv] = missing
	_, err = LoadSecrets(f.getenv)
	if err == nil || strings.Contains(err.Error(), "absent-key-file") || !strings.Contains(err.Error(), AuditKeyEnv) {
		t.Errorf("нет файла: %v", err)
	}
	// Публичный PEM вместо приватного — тоже без содержимого.
	f2 := newFixture(t)
	pub := filepath.Join(filepath.Dir(f2.env[AuditKeyEnv]), "audit.pub")
	f2.env[AuditKeyEnv] = pub
	if _, err := LoadSecrets(f2.getenv); err == nil {
		t.Error("публичный ключ принят как приватный")
	}
}

func TestSecretsNoLeak(t *testing.T) {
	f := newFixture(t)
	s := f.secrets()
	// Маркер ключа API не в ошибках других ключей.
	f.env["AEGIS_MASKER_KEY_FILE"] = f.env["OPENROUTER_API_KEY_FILE"] // не hex
	if _, err := LoadSecrets(f.getenv); err == nil || strings.Contains(err.Error(), f.secret) {
		t.Errorf("утечка/принято: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, v := range []any{s, &s} {
			out := fmt.Sprintf(verb, v)
			for _, bad := range []string{f.secret, f.maskHex, f.privPEM} {
				if strings.Contains(out, bad) {
					t.Errorf("%s: утечка в %q", verb, out)
				}
			}
		}
	}
	if fmt.Sprint(s) != "***" || fmt.Sprintf("%#v", s) != "***" {
		t.Errorf("Secrets печатается не как ***: %q", fmt.Sprint(s))
	}
}
