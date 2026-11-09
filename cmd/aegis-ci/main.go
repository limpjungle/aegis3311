// Команда aegis-ci: проверки CI для политик «четырёх глаз» и подписанного policy bundle (docs/07-governance/ci-four-eyes.md).
// В релиз не входит: запускается только workflow'ами репозитория (go run ./cmd/aegis-ci ...).
//
//	aegis-ci foureyes -repo R -pr N -rules-rev BASE_SHA [-git-dir .]
//	aegis-ci bundle find-pr -repo R -sha S
//	aegis-ci bundle plan    -repo R -sha S [-git-dir .] (-prev FILE [-prev-keys KEYS] | -genesis) -keys KEYS -out unsigned.json [-github-output FILE]
//	aegis-ci bundle sign    -in unsigned.json -key-file F -issuer I -keys KEYS -out policy-bundle.json [-tree DIR]
//	aegis-ci bundle verify  -in FILE -keys KEYS [-commit SHA] [-tree DIR]
//	aegis-ci bundle keygen  -priv FILE -pub FILE
//	aegis-ci sbom -bin FILE -name NAME -out FILE
//
// foureyes — ранний отказ в PR: правила берутся из .github/four-eyes.json на коммите BASE_SHA (базовая ветка), пути — из
// GitHub API, одобрения оцениваются по internal/foureyes. Итог — в stdout и, если задан GITHUB_STEP_SUMMARY, в Markdown.
// bundle plan — первый этап подписи на main: проверяет цепочку (предыдущий подписанный bundle B0 → коммит S), находит
// единственный слитый PR, повторно проверяет его одобрения по правилам из B0 и пишет неподписанный манифест; изменений
// защищённых путей нет — changed=false. bundle sign подписывает манифест ключом из файла и проверяет результат.
// bundle verify — проверка подписанного bundle и его соответствия содержимому, встроенному в эту сборку, либо (с -tree)
// содержимому каталога DIR. В CI проверяющий собирается из коммита предыдущего bundle (B0), а проверяемое дерево — коммит S:
// их содержимое различается, поэтому сверка идёт с деревом S (-tree), а не со встроенным в бинарь B0.
//
// Токен GitHub — из GH_TOKEN (эфемерный токен задания workflow, только чтение): исключение из правила «секреты только
// из файлов». Ключ подписи bundle — только файл (-key-file).
//
// Коды выхода: 0 — успех (plan: в том числе changed=false); 1 — проверка не пройдена или сбой при проверке (fail-closed);
// 2 — ошибка аргументов, конфигурации или ключей (в том числе пустой список ключей подписи).
package main

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
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
	"github.com/limpjungle/aegis3311/internal/bundle"
	"github.com/limpjungle/aegis3311/internal/foureyes"
	"github.com/limpjungle/aegis3311/internal/sbom"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const (
	rulesPath    = ".github/four-eyes.json"
	maxFileBytes = 4 << 20
	baseBranch   = "main"
)

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

func usage(err error) error  { return exitError{2, err} }
func refuse(err error) error { return exitError{1, err} }

type env struct {
	getenv func(string) string
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time
}

func main() {
	e := env{getenv: os.Getenv, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	err := run(ctx, os.Args[1:], e)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "aegis-ci:", err)
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(2)
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("лишние аргументы: %v", fs.Args()))
	}
	return nil
}

func run(ctx context.Context, args []string, e env) error {
	const cmds = "команда: foureyes | bundle | sbom"
	if len(args) == 0 {
		return usage(errors.New(cmds))
	}
	switch args[0] {
	case "foureyes":
		return runFourEyes(ctx, args[1:], e)
	case "sbom":
		return runSBOM(args[1:])
	case "bundle":
		const sub = "bundle: find-pr | plan | sign | verify | keygen"
		if len(args) < 2 {
			return usage(errors.New(sub))
		}
		switch args[1] {
		case "find-pr":
			return runFindPR(ctx, args[2:], e)
		case "plan":
			return runPlan(ctx, args[2:], e)
		case "sign":
			return runSign(args[2:])
		case "verify":
			return runVerify(args[2:], e)
		case "keygen":
			return runKeygen(args[2:])
		}
		return usage(fmt.Errorf("неизвестная подкоманда %q; %s", args[1], sub))
	}
	return usage(fmt.Errorf("неизвестная команда %q; %s", args[0], cmds))
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("%s: больше %d байт", path, maxFileBytes)
	}
	return b, nil
}

// loadKeys читает список ключей подписи bundle (JSON-массив KeySpec; пути относительно каталога файла).
func loadKeys(path string) (bundle.Keyring, error) {
	b, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	var specs []bundle.KeySpec
	if err := strictjson.Decode(b, &specs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range specs {
		if !filepath.IsAbs(specs[i].Path) {
			specs[i].Path = filepath.Join(filepath.Dir(path), specs[i].Path)
		}
	}
	return bundle.LoadKeyring(specs)
}

func newClient(e env, apiURL string) *foureyes.Client {
	return &foureyes.Client{BaseURL: apiURL, Token: e.getenv("GH_TOKEN")}
}

func runFourEyes(ctx context.Context, args []string, e env) error {
	fs := newFlags("foureyes")
	var repo, rev, gitDir, apiURL string
	var n int
	fs.StringVar(&repo, "repo", "", "owner/name")
	fs.IntVar(&n, "pr", 0, "номер PR")
	fs.StringVar(&rev, "rules-rev", "", "коммит базовой ветки, откуда берутся правила")
	fs.StringVar(&gitDir, "git-dir", ".", "каталог git-репозитория")
	fs.StringVar(&apiURL, "api-url", "", "адрес GitHub API (тесты)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if repo == "" || n < 1 || rev == "" {
		return usage(errors.New("foureyes: нужны -repo, -pr и -rules-rev"))
	}
	raw, err := foureyes.Show(gitDir, rev, rulesPath)
	if err != nil {
		return refuse(fmt.Errorf("правила на %s: %w", rev, err))
	}
	rules, err := foureyes.Load(raw)
	if err != nil {
		return refuse(err)
	}
	res, pr, err := evaluatePR(ctx, newClient(e, apiURL), repo, n, rules, nil)
	if err != nil {
		return refuse(err)
	}
	return report(e, res, pr, repo)
}

// evaluatePR собирает данные PR и оценивает одобрения. touched nil — пути берутся из API (PR ещё открыт).
func evaluatePR(ctx context.Context, c *foureyes.Client, repo string, n int, rules foureyes.Rules, touched []string) (foureyes.Result, foureyes.PR, error) {
	pr, err := c.Pull(ctx, repo, n)
	if err != nil {
		return foureyes.Result{}, pr, err
	}
	if touched == nil {
		if touched, err = c.Files(ctx, repo, n); err != nil {
			return foureyes.Result{}, pr, err
		}
	}
	reviews, err := c.Reviews(ctx, repo, n)
	if err != nil {
		return foureyes.Result{}, pr, err
	}
	commits, err := c.Commits(ctx, repo, n)
	if err != nil {
		return foureyes.Result{}, pr, err
	}
	return foureyes.Evaluate(rules, pr, reviews, commits, touched), pr, nil
}

func report(e env, res foureyes.Result, pr foureyes.PR, repo string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## four-eyes: %s#%d\n\n", repo, pr.Number)
	switch {
	case !res.Required:
		b.WriteString("Защищённые пути не затронуты, одобрения четырёх глаз не требуются.\n")
	case res.OK:
		b.WriteString("Одобрения достаточны:\n\n")
		for _, a := range res.Approvers {
			fmt.Fprintf(&b, "- %s (%s)\n", a.Login, a.Group)
		}
	default:
		b.WriteString("Отказ:\n\n")
		for _, r := range res.Reasons {
			fmt.Fprintf(&b, "- %s\n", r)
		}
	}
	fmt.Fprint(e.stdout, b.String())
	if p := e.getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if err := appendFile(p, b.String()); err != nil {
			fmt.Fprintln(e.stderr, "aegis-ci: GITHUB_STEP_SUMMARY:", err)
		}
	}
	if !res.OK {
		return refuse(errors.New("четыре глаза: одобрений недостаточно"))
	}
	return nil
}

func appendFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// findPR — единственный PR, слитый в main именно коммитом sha (squash); иначе push шёл в обход PR.
func findPR(ctx context.Context, c *foureyes.Client, repo, sha string) (foureyes.PR, error) {
	prs, err := c.PullsForCommit(ctx, repo, sha)
	if err != nil {
		return foureyes.PR{}, err
	}
	var found []foureyes.PR
	for _, p := range prs {
		if p.Merged && p.MergeCommitSHA == sha && p.BaseRef == baseBranch {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		return foureyes.PR{}, fmt.Errorf("коммит %s: слитых в %s PR с этим merge-коммитом %d, нужен ровно один (push в обход PR)", sha, baseBranch, len(found))
	}
	return found[0], nil
}

func runFindPR(ctx context.Context, args []string, e env) error {
	fs := newFlags("bundle find-pr")
	var repo, sha, apiURL string
	fs.StringVar(&repo, "repo", "", "owner/name")
	fs.StringVar(&sha, "sha", "", "коммит main")
	fs.StringVar(&apiURL, "api-url", "", "адрес GitHub API (тесты)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if repo == "" || sha == "" {
		return usage(errors.New("bundle find-pr: нужны -repo и -sha"))
	}
	pr, err := findPR(ctx, newClient(e, apiURL), repo, sha)
	if err != nil {
		return refuse(err)
	}
	fmt.Fprintln(e.stdout, pr.Number)
	return nil
}

func writeOutputs(path string, kv ...string) error {
	if path == "" {
		return nil
	}
	return appendFile(path, strings.Join(kv, "\n")+"\n")
}

func runPlan(ctx context.Context, args []string, e env) error {
	fs := newFlags("bundle plan")
	var repo, sha, gitDir, prevPath, prevKeysPath, keysPath, out, ghOut, apiURL string
	var genesis bool
	fs.StringVar(&repo, "repo", "", "owner/name")
	fs.StringVar(&sha, "sha", "", "коммит main, для которого готовится bundle")
	fs.StringVar(&gitDir, "git-dir", ".", "каталог git-репозитория (рабочее дерево на коммите sha)")
	fs.StringVar(&prevPath, "prev", "", "предыдущий подписанный bundle")
	fs.BoolVar(&genesis, "genesis", false, "первый bundle цепочки (предыдущего нет)")
	fs.StringVar(&keysPath, "keys", "", "список открытых ключей подписи (deploy/policy-bundle/keys.json)")
	fs.StringVar(&prevKeysPath, "prev-keys", "", "ключи для проверки предыдущего bundle (из его коммита B0); по умолчанию — -keys")
	fs.StringVar(&out, "out", "", "куда записать неподписанный bundle")
	fs.StringVar(&ghOut, "github-output", "", "файл GITHUB_OUTPUT")
	fs.StringVar(&apiURL, "api-url", "", "адрес GitHub API (тесты)")
	if err := parse(fs, args); err != nil {
		return err
	}
	switch {
	case repo == "" || sha == "" || keysPath == "" || out == "":
		return usage(errors.New("bundle plan: нужны -repo, -sha, -keys и -out"))
	case genesis == (prevPath != ""):
		return usage(errors.New("bundle plan: нужен ровно один из -prev и -genesis"))
	case genesis && prevKeysPath != "":
		return usage(errors.New("bundle plan: -prev-keys не используется с -genesis"))
	}
	keys, err := loadKeys(keysPath)
	if err != nil {
		return usage(err)
	}
	prevKeys := keys
	if prevKeysPath != "" {
		if prevKeys, err = loadKeys(prevKeysPath); err != nil {
			return usage(err)
		}
	}
	head, err := foureyes.RevParse(gitDir, "HEAD")
	if err != nil || head != sha {
		return refuse(fmt.Errorf("рабочее дерево не на коммите %s", sha))
	}

	var prev *bundle.Verified
	var rulesRaw []byte
	rulesFrom := "предыдущего подписанного bundle"
	if genesis {
		rulesRaw, err = foureyes.Show(gitDir, sha, rulesPath)
		rulesFrom = "коммита " + sha + " (genesis: предыдущего bundle нет)"
	} else {
		pb, rerr := readLimited(prevPath)
		if rerr != nil {
			return refuse(fmt.Errorf("предыдущий bundle: %w", rerr))
		}
		if prev, err = bundle.Verify(pb, prevKeys); err != nil {
			return refuse(fmt.Errorf("предыдущий bundle: %w", err))
		}
		if prev.Manifest.Repository != repo {
			return refuse(fmt.Errorf("предыдущий bundle выпущен для %s, а не для %s", prev.Manifest.Repository, repo))
		}
		rulesRaw, err = foureyes.Show(gitDir, prev.Manifest.Commit, rulesPath)
	}
	if err != nil {
		return refuse(fmt.Errorf("правила %s: %w", rulesFrom, err))
	}
	rules, err := foureyes.Load(rulesRaw)
	if err != nil {
		return refuse(err)
	}
	fmt.Fprintf(e.stdout, "правила four-eyes из %s\n", rulesFrom)

	prevCommit := ""
	if prev != nil {
		prevCommit = prev.Manifest.Commit
		changed, err := foureyes.ChangedProtected(gitDir, prevCommit, sha, rules)
		if err != nil {
			return refuse(err)
		}
		if len(changed) == 0 {
			fmt.Fprintf(e.stdout, "защищённые пути не менялись с bundle %d: подписывать нечего\n", prev.Manifest.Sequence)
			return finishPlan(ghOut, "changed=false")
		}
		gap, err := foureyes.ChangedProtected(gitDir, prevCommit, sha+"^", rules)
		if err != nil {
			return refuse(err)
		}
		if len(gap) > 0 {
			return refuse(fmt.Errorf("изменение защищённых путей без подписи (коммиты между %s и %s^): %s", prevCommit, sha, strings.Join(gap, ", ")))
		}
	}
	c := newClient(e, apiURL)
	pr, err := findPR(ctx, c, repo, sha)
	if err != nil {
		return refuse(err)
	}
	if drift, err := foureyes.ChangedProtected(gitDir, sha, pr.HeadSHA, rules); err != nil {
		return refuse(fmt.Errorf("head PR %s: %w (нужен git fetch origin refs/pull/%d/head)", pr.HeadSHA, err, pr.Number))
	} else if len(drift) > 0 {
		return refuse(fmt.Errorf("слитый коммит отличается от head PR в защищённых путях: %s", strings.Join(drift, ", ")))
	}
	touched, err := foureyes.ChangedProtected(gitDir, sha+"^", sha, rules)
	if err != nil {
		return refuse(err)
	}
	res, _, err := evaluatePR(ctx, c, repo, pr.Number, rules, touched)
	if err != nil {
		return refuse(err)
	}
	if !res.Required {
		return refuse(errors.New("коммит не меняет защищённые пути: одобрения подписать нечем (genesis делается PR, меняющим защищённый путь, например deploy/policy-bundle/keys.json)"))
	}
	if !res.OK {
		return refuse(fmt.Errorf("одобрения PR #%d недостаточны: %s", pr.Number, strings.Join(res.Reasons, "; ")))
	}
	content, err := bundle.FromDir(gitDir)
	if err != nil {
		return refuse(err)
	}
	m := bundle.Manifest{Schema: bundle.Schema, Sequence: 1, Repository: repo, Commit: sha,
		IssuedAt: e.now().UTC().Format("2006-01-02T15:04:05Z"), Files: content.Files, Digests: content.Digests(),
		Approvals:  bundle.Approvals{PR: pr.Number, Author: pr.Author, HeadSHA: pr.HeadSHA, Approvers: res.Approvers},
		Signatures: []bundle.Signature{}}
	if prev != nil {
		m.Sequence = prev.Manifest.Sequence + 1
		m.PrevCommit = &prevCommit
	}
	if err := os.WriteFile(out, bundle.Marshal(m), 0o644); err != nil {
		return refuse(err)
	}
	fmt.Fprintf(e.stdout, "bundle %d для %s: PR #%d, одобрили %s\n", m.Sequence, sha, pr.Number, approvers(m.Approvals.Approvers))
	return finishPlan(ghOut, "changed=true", fmt.Sprintf("sequence=%d", m.Sequence))
}

func finishPlan(ghOut string, kv ...string) error {
	if err := writeOutputs(ghOut, kv...); err != nil {
		return refuse(err)
	}
	return nil
}

func approvers(as []bundle.Approver) string {
	var s []string
	for _, a := range as {
		s = append(s, a.Login+" ("+a.Group+")")
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

// contentFor — содержимое для сверки с bundle: файлы каталога tree или, если он не задан, встроенные в этот бинарь.
func contentFor(tree string) (bundle.Content, error) {
	if tree != "" {
		return bundle.FromDir(tree)
	}
	return bundle.Embedded()
}

func runSign(args []string) error {
	fs := newFlags("bundle sign")
	var in, keyFile, issuer, keysPath, out, tree string
	fs.StringVar(&tree, "tree", "", "каталог репозитория для сверки содержимого (по умолчанию — встроенное в бинарь)")
	fs.StringVar(&in, "in", "", "неподписанный bundle")
	fs.StringVar(&keyFile, "key-file", "", "приватный ключ (PEM PKCS#8)")
	fs.StringVar(&issuer, "issuer", "", "issuer подписи")
	fs.StringVar(&keysPath, "keys", "", "список открытых ключей подписи")
	fs.StringVar(&out, "out", "", "куда записать подписанный bundle")
	if err := parse(fs, args); err != nil {
		return err
	}
	if in == "" || keyFile == "" || issuer == "" || keysPath == "" || out == "" {
		return usage(errors.New("bundle sign: нужны -in, -key-file, -issuer, -keys и -out"))
	}
	keys, err := loadKeys(keysPath)
	if err != nil {
		return usage(err)
	}
	signer, err := audit.LoadPrivateKey(keyFile)
	if err != nil {
		return usage(err)
	}
	b, err := readLimited(in)
	if err != nil {
		return refuse(err)
	}
	var m bundle.Manifest
	if err := strictjson.Decode(b, &m); err != nil {
		return refuse(fmt.Errorf("%s: %w", in, err))
	}
	if len(m.Signatures) != 0 {
		return refuse(errors.New("bundle уже подписан"))
	}
	if m, err = bundle.Sign(m, signer, issuer); err != nil {
		return refuse(err)
	}
	signed := bundle.Marshal(m)
	v, err := bundle.Verify(signed, keys)
	if err != nil {
		return refuse(fmt.Errorf("подписанный bundle не проходит проверку: %w", err))
	}
	emb, err := contentFor(tree)
	if err != nil {
		return refuse(err)
	}
	if err := v.Matches(emb); err != nil {
		return refuse(err)
	}
	if err := os.WriteFile(out, signed, 0o644); err != nil {
		return refuse(err)
	}
	return nil
}

func runVerify(args []string, e env) error {
	fs := newFlags("bundle verify")
	var in, keysPath, commit, tree string
	fs.StringVar(&tree, "tree", "", "каталог репозитория для сверки содержимого (по умолчанию — встроенное в бинарь)")
	fs.StringVar(&in, "in", "", "подписанный bundle")
	fs.StringVar(&keysPath, "keys", "", "список открытых ключей подписи")
	fs.StringVar(&commit, "commit", "", "ожидаемый коммит bundle (необязательно)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if in == "" || keysPath == "" {
		return usage(errors.New("bundle verify: нужны -in и -keys"))
	}
	keys, err := loadKeys(keysPath)
	if err != nil {
		return usage(err)
	}
	b, err := readLimited(in)
	if err != nil {
		return refuse(err)
	}
	v, err := bundle.Verify(b, keys)
	if err != nil {
		return refuse(err)
	}
	emb, err := contentFor(tree)
	if err != nil {
		return refuse(err)
	}
	if err := v.Matches(emb); err != nil {
		return refuse(err)
	}
	if commit != "" && v.Manifest.Commit != commit {
		return refuse(fmt.Errorf("bundle выпущен для коммита %s, ожидался %s", v.Manifest.Commit, commit))
	}
	m := v.Manifest
	fmt.Fprintf(e.stdout, "bundle ok: sequence %d, commit %s, PR #%d, одобрили %s\n", m.Sequence, m.Commit, m.Approvals.PR, approvers(m.Approvals.Approvers))
	return nil
}

func runKeygen(args []string) error {
	fs := newFlags("bundle keygen")
	var priv, pub string
	fs.StringVar(&priv, "priv", "", "куда записать приватный ключ (не должен существовать)")
	fs.StringVar(&pub, "pub", "", "куда записать открытый ключ")
	if err := parse(fs, args); err != nil {
		return err
	}
	if priv == "" || pub == "" {
		return usage(errors.New("bundle keygen: нужны -priv и -pub"))
	}
	if _, err := audit.GenerateKey(priv, pub); err != nil {
		return usage(err)
	}
	return nil
}

func runSBOM(args []string) error {
	fs := newFlags("sbom")
	var bin, name, out string
	fs.StringVar(&bin, "bin", "", "Go-бинарь")
	fs.StringVar(&name, "name", "", "имя компонента")
	fs.StringVar(&out, "out", "", "куда записать SBOM (CycloneDX 1.5 JSON)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if bin == "" || name == "" || out == "" {
		return usage(errors.New("sbom: нужны -bin, -name и -out"))
	}
	bi, err := buildinfo.ReadFile(bin)
	if err != nil {
		return refuse(fmt.Errorf("%s: %w", bin, err))
	}
	f, err := os.Open(bin)
	if err != nil {
		return refuse(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return refuse(err)
	}
	b, err := sbom.CycloneDX(bi, name, hex.EncodeToString(h.Sum(nil)))
	if err != nil {
		return refuse(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return refuse(err)
	}
	return nil
}
