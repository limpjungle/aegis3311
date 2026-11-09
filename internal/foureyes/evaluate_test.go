package foureyes

import (
	"strings"
	"testing"
)

const head = "1111111111111111111111111111111111111111"

func approve(login, commit string, id int64) Review {
	return Review{ID: id, Login: login, UserType: "User", State: "APPROVED", CommitID: commit}
}

func TestEvaluate(t *testing.T) {
	r := mustRules(t)
	pr := PR{Number: 5, Author: "zed", HeadSHA: head}
	pol := []string{"policy/a.rego"}
	prof := []string{"data/profiles.json"}
	mixed := []string{"policy/a.rego", "data/profiles.json"}
	gh := []string{".github/x"}
	cases := []struct {
		name     string
		reviews  []Review
		commits  []Commit
		touched  []string
		pr       *PR
		required bool
		ok       bool
		reason   string
		groups   int
	}{
		{name: "нет защищённых путей", touched: []string{"README.md"}, required: false, ok: true},
		{name: "два одобрения из разных групп", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2)}, touched: pol, required: true, ok: true, groups: 2},
		{name: "одобрение на старом commit_id", reviews: []Review{approve("alice", head, 1), approve("carol", "2222222222222222222222222222222222222222", 2)}, touched: pol, required: true, reason: "не на последний коммит"},
		{name: "DISMISSED после APPROVED", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2), {ID: 3, Login: "carol", UserType: "User", State: "DISMISSED", CommitID: head}}, touched: pol, required: true, reason: "одобрений 1"},
		{name: "CHANGES_REQUESTED после APPROVED", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2), approve("dave", head, 4), {ID: 3, Login: "carol", UserType: "User", State: "CHANGES_REQUESTED", CommitID: head}}, touched: pol, required: true, reason: "запрошены изменения"},
		{name: "COMMENTED после APPROVED сохраняет одобрение", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2), {ID: 3, Login: "carol", UserType: "User", State: "COMMENTED", CommitID: head}}, touched: pol, required: true, ok: true, groups: 2},
		{name: "новый APPROVED после CHANGES_REQUESTED", reviews: []Review{{ID: 1, Login: "carol", UserType: "User", State: "CHANGES_REQUESTED", CommitID: head}, approve("carol", head, 2), approve("alice", head, 3)}, touched: pol, required: true, ok: true, groups: 2},
		{name: "соавтор коммита", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2)}, commits: []Commit{{Author: "zed", Committer: "zed"}, {Author: "Carol", Committer: "zed"}}, touched: pol, required: true, reason: "автор или коммиттер"},
		{name: "коммиттер коммита", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2)}, commits: []Commit{{Author: "zed", Committer: "carol"}}, touched: pol, required: true, reason: "автор или коммиттер"},
		{name: "автор PR одобряет сам", reviews: []Review{approve("zed", head, 1), approve("alice", head, 2)}, touched: pol, pr: &PR{Author: "alice", HeadSHA: head}, required: true, reason: "автор PR"},
		{name: "excluded и бот", reviews: []Review{approve("alice", head, 1), {ID: 2, Login: "dependabot[bot]", UserType: "Bot", State: "APPROVED", CommitID: head}}, touched: pol, required: true, reason: "одобрений 1"},
		{name: "бот не User", reviews: []Review{approve("alice", head, 1), {ID: 2, Login: "carol", UserType: "Bot", State: "APPROVED", CommitID: head}}, touched: pol, required: true, reason: "не от человека"},
		{name: "обе из одной группы", reviews: []Review{approve("alice", head, 1), approve("bob", head, 2)}, touched: pol, required: true, reason: "разных групп"},
		{name: "человек в двух группах не заменяет второго", reviews: []Review{approve("alice", head, 1)}, touched: pol, required: true, reason: "одобрений 1"},
		{name: "пересечение групп двух правил: sre не допускается", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2)}, touched: mixed, required: true, reason: "засчитанных одобрений 1"},
		{name: "пересечение групп двух правил", reviews: []Review{approve("alice", head, 1), approve("erin", head, 2)}, touched: mixed, required: true, ok: true, groups: 2},
		{name: "нет обязательной security", reviews: []Review{approve("alice", head, 1), approve("bob", head, 2), approve("carol", head, 3)}, touched: prof, required: true, reason: "обязательными sec"},
		{name: "обязательная security есть", reviews: []Review{approve("alice", head, 1), approve("erin", head, 2)}, touched: prof, required: true, ok: true, groups: 2},
		{name: "нет общей группы", reviews: []Review{approve("carol", head, 1), approve("dave", head, 2)}, touched: []string{"data/profiles.json", ".github/x", "policy/a"}, required: true, reason: "засчитанных одобрений 0"},
		{name: "CHANGES_REQUESTED члена группы блокирует", reviews: []Review{approve("alice", head, 1), approve("erin", head, 2), {ID: 3, Login: "dave", UserType: "User", State: "CHANGES_REQUESTED", CommitID: head}}, touched: pol, required: true, reason: "запрошены изменения: dave"},
		{name: "CHANGES_REQUESTED постороннего не блокирует", reviews: []Review{approve("alice", head, 1), approve("erin", head, 2), {ID: 3, Login: "outsider", UserType: "User", State: "CHANGES_REQUESTED", CommitID: head}}, touched: pol, required: true, ok: true, groups: 2},
		{name: "одобрение постороннего не считается", reviews: []Review{approve("alice", head, 1), approve("outsider", head, 2)}, touched: pol, required: true, reason: "нет в допустимой группе"},
		{name: "регистр логина", reviews: []Review{approve("ALICE", head, 1), approve("Erin", head, 2)}, touched: pol, required: true, ok: true, groups: 2},
		{name: "нет ревью", touched: pol, required: true, reason: "засчитанных одобрений 0"},
		{name: "три человека, добор до двух групп", reviews: []Review{approve("alice", head, 1), approve("bob", head, 2), approve("carol", head, 3)}, touched: pol, required: true, ok: true, groups: 2},
		{name: ".github: доступны owners и sre", reviews: []Review{approve("alice", head, 1), approve("carol", head, 2)}, touched: gh, required: true, ok: true, groups: 2},
		{name: ".github: security не допускается", reviews: []Review{approve("alice", head, 1), approve("erin", head, 2)}, touched: gh, required: true, reason: "нет в допустимой группе"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := pr
			if c.pr != nil {
				p = *c.pr
			}
			res := Evaluate(r, p, c.reviews, c.commits, c.touched)
			if res.Required != c.required || res.OK != c.ok {
				t.Fatalf("Required=%v OK=%v, ожидалось %v %v; причины %v", res.Required, res.OK, c.required, c.ok, res.Reasons)
			}
			if c.reason != "" && !strings.Contains(strings.Join(res.Reasons, "|"), c.reason) {
				t.Errorf("причины %v не содержат %q", res.Reasons, c.reason)
			}
			if c.ok && c.required {
				gs := map[string]bool{}
				for _, a := range res.Approvers {
					gs[a.Group] = true
				}
				if len(res.Approvers) < 2 || len(gs) < 2 || len(gs) != c.groups && c.groups > 2 {
					t.Errorf("approvers %+v", res.Approvers)
				}
				if len(res.Reasons) != 0 {
					t.Errorf("при OK причин быть не должно: %v", res.Reasons)
				}
			} else if res.Approvers != nil {
				t.Errorf("при отказе approvers должен быть пуст: %+v", res.Approvers)
			}
		})
	}
}

// Назначение «человек → группа» подбирается перебором: alice в двух группах, bob только в одной — alice уходит в другую.
func TestEvaluateAssignment(t *testing.T) {
	r, err := Load([]byte(`{"schema":"aegisops/four-eyes/v1","min_approvals":2,"min_groups":2,
	"groups":{"a":["alice","bob"],"b":["alice"]},"excluded":[],"protected":[{"path":"p/","groups":["a","b"],"require":["b"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res := Evaluate(r, PR{Author: "zed", HeadSHA: head}, []Review{approve("alice", head, 1), approve("bob", head, 2)}, nil, []string{"p/x"})
	if !res.OK {
		t.Fatalf("отказ: %v", res.Reasons)
	}
	for _, a := range res.Approvers {
		if (a.Login == "alice" && a.Group != "b") || (a.Login == "bob" && a.Group != "a") {
			t.Errorf("неверное назначение: %+v", res.Approvers)
		}
	}
}

func TestEvaluateTooManyCommits(t *testing.T) {
	r := mustRules(t)
	rv := []Review{approve("alice", head, 1), approve("erin", head, 2)}
	many := make([]Commit, MaxPRCommits)
	if res := Evaluate(r, PR{Author: "zed", HeadSHA: head}, rv, many[:MaxPRCommits-1], []string{"policy/a"}); !res.OK {
		t.Fatalf("249 коммитов: %v", res.Reasons)
	}
	res := Evaluate(r, PR{Author: "zed", HeadSHA: head}, rv, many, []string{"policy/a"})
	if res.OK || !res.Required || !strings.Contains(strings.Join(res.Reasons, "|"), "слишком много коммитов") {
		t.Errorf("250 коммитов должны быть отказом: %+v", res)
	}
	// Без защищённых путей предел не мешает.
	if res := Evaluate(r, PR{Author: "zed", HeadSHA: head}, nil, many, []string{"README.md"}); !res.OK {
		t.Error("незащищённые пути не требуют проверки соавторов")
	}
}
