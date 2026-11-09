package main

import (
	"fmt"
	"strings"
	"testing"
)

// Обходы bundle plan: каждый сценарий обязан закончиться отказом (код 1), подписываемого манифеста быть не должно.

func (h *harness) mustRefuse(sha, prev, want string) {
	h.t.Helper()
	text, outs, err := h.plan(sha, "-prev", prev)
	if code(err) != 1 || (want != "" && !strings.Contains(err.Error(), want)) {
		h.t.Fatalf("ожидался отказ с %q: err=%v\n%s", want, err, text)
	}
	if strings.Contains(outs, "changed=true") {
		h.t.Fatalf("при отказе changed=true не пишется: %s", outs)
	}
}

func TestPlanBypasses(t *testing.T) {
	t.Run("несколько PR для одного коммита", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob", "carol")
		h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", m2)] = "[" + pullJSON(2, "zed", h2, m2) + "," + pullJSON(3, "zed", h2, m2) + "]"
		h.mustRefuse(m2, b1, "нужен ровно один")
	})
	t.Run("PR не в main", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob", "carol")
		h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", m2)] = "[" + strings.Replace(pullJSON(2, "zed", h2, m2), `"ref":"main"`, `"ref":"feature"`, 1) + "]"
		h.mustRefuse(m2, b1, "в обход PR")
	})
	t.Run("PR не слит", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob", "carol")
		h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", m2)] = "[" + pullJSON(2, "zed", h2, "") + "]"
		h.mustRefuse(m2, b1, "в обход PR")
	})
	t.Run("merge_commit_sha другого коммита", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob", "carol")
		h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", m2)] = "[" + pullJSON(2, "zed", h2, strings.Repeat("9", 40)) + "]"
		h.mustRefuse(m2, b1, "в обход PR")
	})
	t.Run("ошибка API закрывает отказом", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, _ := h.squash(map[string]string{"deploy/y.txt": "y"}) // маршрутов нет: 404
		h.mustRefuse(m2, b1, "")
	})
	t.Run("одобрения на старом head", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob")
		old := strings.Repeat("7", 40)
		h.routes["/repos/o/r/pulls/2/reviews"] = "[" + reviewJSON(10, "bob", "APPROVED", h2) + "," + reviewJSON(11, "carol", "APPROVED", old) + "]"
		h.mustRefuse(m2, b1, "недостаточны")
	})
	t.Run("соавтор коммитов PR одобряет", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob", "carol")
		h.routes["/repos/o/r/pulls/2/commits"] = `[{"author":{"login":"zed"},"committer":{"login":"zed"}},{"author":{"login":"Carol"},"committer":{"login":"web-flow"}}]`
		h.mustRefuse(m2, b1, "автор или коммиттер")
	})
	t.Run("автор PR среди одобривших", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "zed", "carol") // zed — автор; в группах его нет, но проверяем и автора из группы ниже
		h.mustRefuse(m2, b1, "недостаточны")
	})
	t.Run("бот одобряет", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob")
		h.routes["/repos/o/r/pulls/2/reviews"] = "[" + reviewJSON(10, "bob", "APPROVED", h2) +
			`,{"id":11,"user":{"login":"carol","type":"Bot"},"state":"APPROVED","commit_id":"` + h2 + `"}]`
		h.mustRefuse(m2, b1, "недостаточны")
	})
	t.Run("действующий CHANGES_REQUESTED", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice", "carol")
		h.routes["/repos/o/r/pulls/2/reviews"] = "[" + reviewJSON(10, "alice", "APPROVED", h2) + "," + reviewJSON(11, "carol", "APPROVED", h2) +
			"," + reviewJSON(12, "bob", "CHANGES_REQUESTED", h2) + "]"
		h.mustRefuse(m2, b1, "запрошены изменения")
	})
	t.Run("DISMISSED после APPROVED", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice", "carol")
		h.routes["/repos/o/r/pulls/2/reviews"] = "[" + reviewJSON(10, "alice", "APPROVED", h2) + "," + reviewJSON(11, "carol", "APPROVED", h2) +
			"," + reviewJSON(12, "carol", "DISMISSED", h2) + "]"
		h.mustRefuse(m2, b1, "недостаточны")
	})
	t.Run("один человек в разном регистре — одно одобрение", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice", "ALICE")
		h.mustRefuse(m2, b1, "недостаточны")
	})
	// PR вписывает в группу sec нового человека и приносит его одобрение: правила — из B0, где его в группе нет.
	t.Run("самозачисление в группу тем же PR", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		self := strings.Replace(testRules, `"sec":["carol"]`, `"sec":["carol","mallory"]`, 1)
		m2, h2 := h.squash(map[string]string{".github/four-eyes.json": self, "deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice", "mallory")
		h.mustRefuse(m2, b1, "недостаточны")
	})
	t.Run("PR убирает защиту пути и меняет его", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		weak := strings.Replace(testRules, `{"path":"deploy/","groups":["owners","sec"],"require":[]},`, "", 1)
		m2, h2 := h.squash(map[string]string{".github/four-eyes.json": weak, "deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice")
		h.mustRefuse(m2, b1, "недостаточны")
	})
	t.Run("подмена защищённого файла после одобрения", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"policy/aegis/x.txt": "ok"})
		_ = h2
		// Одобренный head содержит другое содержимое, чем слитый коммит.
		gitIn(t, h.repo, "checkout", "-q", "-B", "other", "HEAD~1")
		h.write("policy/aegis/x.txt", "other")
		other := h.commit("other")
		gitIn(t, h.repo, "checkout", "-q", "main")
		h.routePR(2, m2, other, "alice", "carol")
		h.mustRefuse(m2, b1, "отличается от head")
	})
	t.Run("PR из коммитов без защищённых изменений на S^..S", func(t *testing.T) {
		// Защищённое изменение уже в S^ (не подписано), а S сам его не меняет: цепочка разорвана.
		h := newHarness(t)
		b1, _ := h.genesis()
		h.write("deploy/direct.txt", "x")
		h.commit("direct, без PR")
		h.write("README.md", "42")
		s := h.commit("readme")
		h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", s)] = "[]"
		h.mustRefuse(s, b1, "без подписи")
	})
}

// Смена режима файла (исполняемый бит) — изменение защищённого пути.
func TestPlanModeChangeIsProtectedChange(t *testing.T) {
	h := newHarness(t)
	b1, _ := h.genesis()
	gitIn(t, h.repo, "update-index", "--chmod=+x", "deploy/g.txt")
	s := gitIn(t, h.repo, "commit", "-q", "-m", "chmod")
	_ = s
	sha := gitIn(t, h.repo, "rev-parse", "HEAD")
	h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", sha)] = "[]"
	h.mustRefuse(sha, b1, "в обход PR")
}
