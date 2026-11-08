package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// prepRelease готовит release.json с двумя подписями (ivanov + petrov) без публикации.
func prepRelease(t *testing.T, r *rig, name string) (one, two string) {
	t.Helper()
	one, two = filepath.Join(r.dir, name+"-1.json"), filepath.Join(r.dir, name+"-2.json")
	if _, _, code := r.run("release", "-key", r.key("ivanov"), "-out", one); code != 0 {
		t.Fatal("release")
	}
	if _, _, code := r.run("cosign", "-key", r.key("petrov"), "-in", one, "-out", two); code != 0 {
		t.Fatal("cosign -out")
	}
	return
}

// Проверка плана: publish run отказывает, если канал с возможным stop не прочитан; stop в канале не затирается.
func TestPublishRunRefusesWhenChannelUnreadable(t *testing.T) {
	r := newRig(t)
	_, signed := prepRelease(t, r, "rel")
	r.clk.add(time.Second)
	if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-global", "-channels", "oob"); code != 0 {
		t.Fatal("stop")
	}
	before := r.cloud.oob()
	r.cloud.failS3Get = true // канал oob не читается, а записывается
	_, errs, code := r.run("publish", "-in", signed)
	r.cloud.failS3Get = false
	if code == 0 {
		t.Errorf("publish run при нечитаемом канале завершился кодом 0 (stderr: %s)", errs)
	}
	if after := r.cloud.oob(); after != before {
		t.Errorf("stop в oob затёрт старым run вслепую")
	}
}

// Проверка плана: cosign -publish для run не должен затирать более новый stop в каналах.
func TestCosignPublishRefusesOverNewerStop(t *testing.T) {
	r := newRig(t)
	one := filepath.Join(r.dir, "rel.json")
	if _, _, code := r.run("release", "-key", r.key("ivanov"), "-out", one); code != 0 {
		t.Fatal("release")
	}
	r.clk.add(time.Second)
	if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-global"); code != 0 {
		t.Fatal("stop")
	}
	stopDoc := r.cloud.oob()
	_, errs, code := r.run("cosign", "-key", r.key("petrov"), "-in", one, "-publish")
	if code == 0 {
		t.Errorf("cosign -publish затёр более новый stop (stderr: %s)", errs)
	}
	if r.cloud.oob() != stopDoc || r.cloud.cm != stopDoc {
		t.Error("stop в каналах заменён старым run")
	}
}

// publish run отказывает над новым stop в любом канале (уже проверено для обоих каналов читаемых).
func TestPublishRunOverStopInSingleChannel(t *testing.T) {
	for _, ch := range []string{"configmap", "oob"} {
		r := newRig(t)
		_, signed := prepRelease(t, r, "rel")
		r.clk.add(time.Second)
		if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-cluster", "x", "-channels", ch); code != 0 {
			t.Fatal("stop")
		}
		if _, _, code := r.run("publish", "-in", signed); code != 1 {
			t.Errorf("%s: publish над stop: код %d", ch, code)
		}
	}
}

// Новый release (новее stop) снимает; publish проходит.
func TestFreshReleaseAfterStopPublishes(t *testing.T) {
	r := newRig(t)
	r.run("stop", "-key", r.key("sidorov"), "-global")
	r.clk.add(time.Second)
	_, signed := prepRelease(t, r, "new")
	if out, errs, code := r.run("publish", "-in", signed); code != 0 {
		t.Fatalf("код %d\n%s\n%s", code, out, errs)
	}
}

// cosign отказывает: просрочен, из будущего, global/cluster.
func TestCosignRefusals(t *testing.T) {
	r := newRig(t)
	one := filepath.Join(r.dir, "rel.json")
	r.run("release", "-key", r.key("ivanov"), "-out", one, "-ttl", "1m")
	r.clk.add(2 * time.Minute)
	if _, _, code := r.run("cosign", "-key", r.key("petrov"), "-in", one, "-out", one+".o"); code != 1 {
		t.Errorf("cosign просроченного: код %d", code)
	}
	// из будущего
	r2 := newRig(t)
	two := filepath.Join(r2.dir, "rel.json")
	r2.clk.add(time.Hour)
	r2.run("release", "-key", r2.key("ivanov"), "-out", two)
	r2.clk.add(-time.Hour)
	if _, _, code := r2.run("cosign", "-key", r2.key("petrov"), "-in", two, "-out", two+".o"); code != 1 {
		t.Errorf("cosign из будущего: код %d", code)
	}
	// stop global/cluster — вторая подпись не принимается
	r3 := newRig(t)
	st := filepath.Join(r3.dir, "stop.json")
	r3.run("stop", "-key", r3.key("ivanov"), "-global", "-out", st)
	if _, _, code := r3.run("cosign", "-key", r3.key("petrov"), "-in", st, "-out", st+".o"); code != 1 {
		t.Errorf("cosign global: код %d", code)
	}
	cl := filepath.Join(r3.dir, "cl.json")
	r3.run("stop", "-key", r3.key("ivanov"), "-cluster", "prod-eu-1", "-out", cl)
	if _, _, code := r3.run("cosign", "-key", r3.key("petrov"), "-in", cl, "-out", cl+".o"); code != 1 {
		t.Errorf("cosign cluster: код %d", code)
	}
}

// publish одноподписного run, подписи renewer вместо второго oncall.
func TestPublishRunNeedsTwoOncall(t *testing.T) {
	r := newRig(t)
	one := filepath.Join(r.dir, "rel.json")
	r.run("release", "-key", r.key("ivanov"), "-out", one)
	if _, _, code := r.run("cosign", "-key", r.key("renewer-a"), "-in", one, "-out", one+".o"); code != 1 {
		t.Errorf("renewer как второй подписант run: код %d", code)
	}
	if _, _, code := r.run("release", "-key", r.key("renewer-a"), "-out", one+".r"); code != 2 {
		t.Errorf("release ключом renewer: код %d", code)
	}
}

// Renew отказывает при одноподписном stop в любом канале и не затирает его; слот не публикуется.
func TestRenewRefusesOnSingleSigStopInOneChannel(t *testing.T) {
	r := newRig(t)
	_, signed := prepRelease(t, r, "rel")
	if _, _, code := r.run("publish", "-in", signed); code != 0 {
		t.Fatal("publish")
	}
	r.clk.add(2 * time.Hour)
	if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-cluster", "x", "-channels", "configmap"); code != 0 {
		t.Fatal("stop")
	}
	cm := r.cloud.cm
	for _, n := range []string{"renewer-a", "renewer-b"} {
		if _, _, code := r.run("renew", "-key", r.key(n)); code != 1 {
			t.Errorf("renew %s при stop: код %d", n, code)
		}
	}
	if r.cloud.cm != cm {
		t.Error("renew затёр stop")
	}
	// ключ oncall не может продлевать
	if _, _, code := r.run("renew", "-key", r.key("ivanov")); code != 1 {
		t.Errorf("renew ключом oncall: код %d", code)
	}
}

// Роль: stop любым ключом keyring (в том числе renewer) допустим с одной подписью; чужой ключ — нет.
func TestStopKeyMustBeInKeyring(t *testing.T) {
	r := newRig(t)
	foreign := filepath.Join(r.dir, "foreign.pem")
	if _, err := os.Stat(foreign); err == nil {
		t.Fatal("ключ уже существует")
	}
	if _, _, code := r.run("stop", "-key", foreign, "-global"); code != 2 {
		t.Errorf("stop без ключа: код %d", code)
	}
	if _, _, code := r.run("stop", "-key", r.key("renewer-a"), "-global"); code != 0 {
		t.Errorf("stop ключом renewer: код %d", code)
	}
}

// Runbook, упр. 4: action-only stop одной подписью публикуется поверх run, и подтверждения нет — для работы LLM нужна
// вторая подпись oncall (cosign -publish). Тест фиксирует рабочий путь.
func TestActionStopNeedsSecondSignatureToKeepRouterRunning(t *testing.T) {
	r := newRig(t)
	_, signed := prepRelease(t, r, "rel")
	r.run("publish", "-in", signed)
	r.clk.add(time.Second)
	if _, _, code := r.run("stop", "-key", r.key("ivanov"), "-action", "workload.restart"); code != 0 {
		t.Fatal("stop -action")
	}
	st, _, _ := r.run("status", "-cluster", "prod-eu-1")
	if !strings.Contains(st, `"stopped": true`) {
		t.Errorf("ожидалось stopped:true (no_confirmation) после одноподписного action-stop: %s", st)
	}
	r.clk.add(time.Second)
	out := filepath.Join(r.dir, "act.json")
	r.run("stop", "-key", r.key("ivanov"), "-action", "workload.restart", "-out", out)
	if _, _, code := r.run("cosign", "-key", r.key("petrov"), "-in", out, "-publish"); code != 0 {
		t.Fatal("cosign -publish action-stop")
	}
	st, _, _ = r.run("status", "-cluster", "prod-eu-1")
	if !strings.Contains(st, `"stopped": false`) || !strings.Contains(st, "workload.restart") {
		t.Errorf("после двух подписей: %s", st)
	}
}

// Ответ kube API, который не разбирается (прокси, обрезанное тело), не равен «пустому каналу»: stop мог быть в нём.
func TestPublishRunRefusesOnGarbledConfigMapResponse(t *testing.T) {
	r := newRig(t)
	_, signed := prepRelease(t, r, "rel")
	r.clk.add(time.Second)
	if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-global", "-channels", "configmap"); code != 0 {
		t.Fatal("stop")
	}
	stopDoc := r.cloud.cm
	r.cloud.garbleCMGet = true
	_, errs, code := r.run("publish", "-in", signed)
	r.cloud.garbleCMGet = false
	if code == 0 || r.cloud.cm != stopDoc {
		t.Errorf("непрочитанный ответ kube API принят за пустой канал: код %d, stop затёрт=%v (%s)", code, r.cloud.cm != stopDoc, errs)
	}
}
