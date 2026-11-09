package foureyes

import (
	"fmt"
	"sort"
	"strings"

	"github.com/limpjungle/aegis3311/internal/bundle"
)

// PR — данные запроса слияния, нужные для оценки.
type PR struct {
	Number         int
	Author         string
	HeadSHA        string
	BaseRef        string
	MergeCommitSHA string
	Merged         bool
}

// Review — ревью PR (GET /pulls/{n}/reviews).
type Review struct {
	ID       int64
	Login    string
	UserType string // User | Bot | ...
	State    string // APPROVED | CHANGES_REQUESTED | DISMISSED | COMMENTED | PENDING
	CommitID string
}

// Commit — автор и коммиттер коммита PR (логины GitHub; пусто, если коммит не связан с аккаунтом).
type Commit struct{ Author, Committer string }

// Result — итог оценки. Required=false — защищённые пути не затронуты, одобрения не нужны.
type Result struct {
	Required  bool
	OK        bool
	Approvers []bundle.Approver
	Reasons   []string
}

type person struct {
	login    string
	reviewID int64
	groups   []string // допустимые группы человека
}

// Evaluate оценивает одобрения PR для затронутых защищённых путей.
//
// Берётся последнее ревью каждого пользователя среди APPROVED, CHANGES_REQUESTED и DISMISSED (COMMENTED игнорируется).
// Одобрение засчитывается, если оно на текущем head PR, дано человеком (type User), не автором PR, не из excluded,
// не автором и не коммиттером коммитов PR и если человек входит в группу, допустимую для ВСЕХ затронутых правил.
// Нужно не меньше min_approvals разных людей, которых можно назначить в min_groups разных групп так, чтобы покрыть
// каждую группу из require. Действующий CHANGES_REQUESTED от члена допустимой группы — отказ. Соавторы, указанные только
// трейлером Co-authored-by, в списке коммитов GitHub не видны (допущение); при 250 и более коммитах — отказ.
func Evaluate(r Rules, pr PR, reviews []Review, commits []Commit, touched []string) Result {
	rules := r.Touched(touched)
	if len(rules) == 0 {
		return Result{Required: false, OK: true}
	}
	res := Result{Required: true}
	var notes []string // почему отдельные одобрения не засчитаны; показываются только при отказе
	fail := func(format string, a ...any) { res.Reasons = append(res.Reasons, fmt.Sprintf(format, a...)) }
	note := func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) }

	if len(commits) >= MaxPRCommits { // список мог быть усечён GitHub'ом: соавторов не исключить
		fail("%v (%d коммитов, предел API %d)", ErrTooManyCommits, len(commits), MaxPRCommits)
		return res
	}
	allowed := map[string]bool{}
	for _, g := range rules[0].Groups {
		allowed[g] = true
	}
	required := map[string]bool{}
	for _, rl := range rules {
		in := map[string]bool{}
		for _, g := range rl.Groups {
			in[g] = true
		}
		for g := range allowed {
			if !in[g] {
				delete(allowed, g)
			}
		}
		for _, g := range rl.Require {
			required[g] = true
		}
	}
	if len(allowed) == 0 {
		fail("у затронутых правил нет общей группы одобряющих")
		return res
	}

	barred := map[string]string{strings.ToLower(pr.Author): "автор PR"}
	for _, e := range r.Excluded {
		barred[strings.ToLower(e)] = "в списке excluded"
	}
	for _, c := range commits {
		for _, l := range []string{c.Author, c.Committer} {
			if l != "" {
				if _, ok := barred[strings.ToLower(l)]; !ok {
					barred[strings.ToLower(l)] = "автор или коммиттер коммита PR"
				}
			}
		}
	}

	last := map[string]Review{}
	for _, rv := range reviews {
		switch rv.State {
		case "APPROVED", "CHANGES_REQUESTED", "DISMISSED":
			k := strings.ToLower(rv.Login)
			if p, ok := last[k]; !ok || rv.ID > p.ID {
				last[k] = rv
			}
		}
	}
	logins := make([]string, 0, len(last))
	for k := range last {
		logins = append(logins, k)
	}
	sort.Strings(logins)

	var people []person
	for _, k := range logins {
		rv := last[k]
		groups := memberGroups(r, k, allowed)
		switch rv.State {
		case "CHANGES_REQUESTED":
			if len(groups) > 0 {
				fail("запрошены изменения: %s", rv.Login)
			}
		case "APPROVED":
			switch why, bar := barred[k]; {
			case rv.CommitID != pr.HeadSHA:
				note("одобрение %s дано не на последний коммит PR", rv.Login)
			case rv.UserType != "User":
				note("одобрение %s не от человека (type %s)", rv.Login, rv.UserType)
			case bar:
				note("одобрение %s не засчитано: %s", rv.Login, why)
			case len(groups) == 0:
				note("одобрение %s не засчитано: нет в допустимой группе", rv.Login)
			default:
				people = append(people, person{login: rv.Login, reviewID: rv.ID, groups: groups})
			}
		}
	}

	if len(people) < r.MinApprovals {
		fail("засчитанных одобрений %d, нужно не меньше %d", len(people), r.MinApprovals)
	}
	if chosen, ok := assign(r, people, required); ok {
		res.Approvers = chosen
	} else if len(people) >= r.MinApprovals {
		if len(required) > 0 {
			fail("одобрения не покрывают %d разных групп с обязательными %s", r.MinGroups, joinSet(required))
		} else {
			fail("одобрения не покрывают %d разных групп", r.MinGroups)
		}
	}
	res.OK = len(res.Reasons) == 0 && res.Approvers != nil
	if !res.OK {
		res.Approvers = nil
		res.Reasons = append(res.Reasons, notes...)
		if len(res.Reasons) == 0 {
			res.Reasons = []string{"одобрения не подходят"}
		}
	}
	return res
}

func memberGroups(r Rules, loginLower string, allowed map[string]bool) []string {
	var out []string
	for g := range allowed {
		for _, m := range r.Groups[g] {
			if strings.ToLower(m) == loginLower {
				out = append(out, g)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func joinSet(s map[string]bool) string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// assign подбирает назначение «человек → группа»: наименьшее множество групп S, содержащее все обязательные и не меньше
// min_groups групп, в котором каждой группе назначен свой человек; затем лишние люди добираются до min_approvals.
func assign(r Rules, people []person, required map[string]bool) ([]bundle.Approver, bool) {
	var groups []string
	seen := map[string]bool{}
	for _, p := range people {
		for _, g := range p.groups {
			if !seen[g] {
				seen[g] = true
				groups = append(groups, g)
			}
		}
	}
	sort.Strings(groups)
	for g := range required {
		if !seen[g] {
			return nil, false
		}
	}
	var best []string
	for mask := 1; mask < 1<<len(groups); mask++ {
		var sub []string
		for i, g := range groups {
			if mask>>i&1 == 1 {
				sub = append(sub, g)
			}
		}
		if len(sub) < r.MinGroups || (best != nil && len(sub) >= len(best)) {
			continue
		}
		ok := true
		for g := range required {
			if !contains(sub, g) {
				ok = false
			}
		}
		if ok && matchAll(people, sub) != nil {
			best = sub
		}
	}
	if best == nil {
		return nil, false
	}
	m := matchAll(people, best)
	used := map[int]bool{}
	var out []bundle.Approver
	for gi, pi := range m {
		used[pi] = true
		out = append(out, bundle.Approver{Login: people[pi].login, Group: best[gi], ReviewID: people[pi].reviewID})
	}
	for i, p := range people { // добор до min_approvals: лишние люди в первую свою группу
		if len(out) >= r.MinApprovals {
			break
		}
		if !used[i] {
			out = append(out, bundle.Approver{Login: p.login, Group: p.groups[0], ReviewID: p.reviewID})
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Login) < strings.ToLower(out[j].Login) })
	return out, len(out) >= r.MinApprovals
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// matchAll — паросочетание, насыщающее все группы sub (индекс группы → индекс человека); nil, если такого нет.
func matchAll(people []person, sub []string) map[int]int {
	owner := map[int]int{} // человек → группа
	var try func(g int, vis map[int]bool) bool
	try = func(g int, vis map[int]bool) bool {
		for pi, p := range people {
			if vis[pi] || !contains(p.groups, sub[g]) {
				continue
			}
			vis[pi] = true
			if prev, taken := owner[pi]; !taken || try(prev, vis) {
				owner[pi] = g
				return true
			}
		}
		return false
	}
	for g := range sub {
		if !try(g, map[int]bool{}) {
			return nil
		}
	}
	out := map[int]int{}
	for pi, g := range owner {
		out[g] = pi
	}
	return out
}
