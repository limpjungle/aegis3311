package foureyes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.github.com"
	perPage        = 100
	maxPages       = 30
	maxBodyBytes   = 8 << 20
	// MaxPRCommits — GitHub отдаёт в /pulls/{n}/commits не больше 250 коммитов: при таком числе список может быть усечён,
	// и соавторов нельзя исключить из одобряющих. Проверка отказывает (fail-closed).
	MaxPRCommits = 250
	apiVersion   = "2022-11-28"
)

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	nextRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)
)

// Client — клиент GitHub REST API, только чтение. Токен берётся из GH_TOKEN: это исключение из правила «секреты только
// из файлов» — токен эфемерный (github.token задания workflow), живёт на время job'а и даёт только чтение.
type Client struct {
	BaseURL string // по умолчанию https://api.github.com
	Token   string
	HTTP    *http.Client
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) base() string {
	if c.BaseURL == "" {
		return defaultBaseURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}

// get выполняет один GET и возвращает тело и заголовок Link.
func (c *Client) get(ctx context.Context, u string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("github: %w", err)
	}
	if len(b) > maxBodyBytes {
		return nil, "", fmt.Errorf("github: ответ больше %d байт", maxBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("github: %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return b, resp.Header.Get("Link"), nil
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	b, _, err := c.get(ctx, c.base()+path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// pages собирает все страницы списка (Link rel="next"); больше maxPages страниц — ошибка, а не молчаливое усечение.
func (c *Client) pages(ctx context.Context, path string, each func(raw []byte) error) error {
	next := c.base() + path + "?per_page=" + fmt.Sprint(perPage)
	if strings.Contains(path, "?") {
		next = c.base() + path + "&per_page=" + fmt.Sprint(perPage)
	}
	for n := 0; ; n++ {
		if n >= maxPages {
			return fmt.Errorf("github: %s: больше %d страниц", path, maxPages)
		}
		b, link, err := c.get(ctx, next)
		if err != nil {
			return err
		}
		if err := each(b); err != nil {
			return err
		}
		m := nextRe.FindStringSubmatch(link)
		if m == nil {
			return nil
		}
		nu, err := url.Parse(m[1])
		if err != nil {
			return fmt.Errorf("github: Link: %w", err)
		}
		bu, _ := url.Parse(c.base())
		if nu.Host != bu.Host || nu.Scheme != bu.Scheme { // токен не уходит на чужой хост
			return errors.New("github: Link указывает на другой хост")
		}
		next = m[1]
	}
}

func checkRepo(repo string) error {
	if !repoRe.MatchString(repo) {
		return fmt.Errorf("github: некорректный репозиторий %q", repo)
	}
	return nil
}

// ErrTooManyCommits — в PR слишком много коммитов, чтобы проверить соавторов.
var ErrTooManyCommits = errors.New("слишком много коммитов в PR для проверки соавторов")

type apiUser struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// Pull — PR по номеру.
func (c *Client) Pull(ctx context.Context, repo string, n int) (PR, error) {
	if err := checkRepo(repo); err != nil {
		return PR{}, err
	}
	var raw struct {
		Number         int     `json:"number"`
		User           apiUser `json:"user"`
		Merged         bool    `json:"merged"`
		MergeCommitSHA *string `json:"merge_commit_sha"`
		Head           struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/pulls/%d", repo, n), &raw); err != nil {
		return PR{}, err
	}
	pr := PR{Number: raw.Number, Author: raw.User.Login, HeadSHA: raw.Head.SHA, BaseRef: raw.Base.Ref, Merged: raw.Merged}
	if raw.MergeCommitSHA != nil {
		pr.MergeCommitSHA = *raw.MergeCommitSHA
	}
	return pr, nil
}

// Reviews — ревью PR в порядке GitHub (хронологически).
func (c *Client) Reviews(ctx context.Context, repo string, n int) ([]Review, error) {
	if err := checkRepo(repo); err != nil {
		return nil, err
	}
	var out []Review
	err := c.pages(ctx, fmt.Sprintf("/repos/%s/pulls/%d/reviews", repo, n), func(b []byte) error {
		var page []struct {
			ID       int64   `json:"id"`
			User     apiUser `json:"user"`
			State    string  `json:"state"`
			CommitID string  `json:"commit_id"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, r := range page {
			out = append(out, Review{ID: r.ID, Login: r.User.Login, UserType: r.User.Type, State: r.State, CommitID: r.CommitID})
		}
		return nil
	})
	return out, err
}

// Commits — коммиты PR с их авторами и коммиттерами.
func (c *Client) Commits(ctx context.Context, repo string, n int) ([]Commit, error) {
	if err := checkRepo(repo); err != nil {
		return nil, err
	}
	var out []Commit
	err := c.pages(ctx, fmt.Sprintf("/repos/%s/pulls/%d/commits", repo, n), func(b []byte) error {
		var page []struct {
			Author    *apiUser `json:"author"`
			Committer *apiUser `json:"committer"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, x := range page {
			var cm Commit
			if x.Author != nil {
				cm.Author = x.Author.Login
			}
			if x.Committer != nil {
				cm.Committer = x.Committer.Login
			}
			out = append(out, cm)
		}
		return nil
	})
	if err == nil && len(out) >= MaxPRCommits {
		return out, ErrTooManyCommits
	}
	return out, err
}

// Files — пути, изменённые PR (для переименования — и старый, и новый путь).
func (c *Client) Files(ctx context.Context, repo string, n int) ([]string, error) {
	if err := checkRepo(repo); err != nil {
		return nil, err
	}
	var out []string
	err := c.pages(ctx, fmt.Sprintf("/repos/%s/pulls/%d/files", repo, n), func(b []byte) error {
		var page []struct {
			Filename string `json:"filename"`
			Previous string `json:"previous_filename"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, f := range page {
			out = append(out, f.Filename)
			if f.Previous != "" {
				out = append(out, f.Previous)
			}
		}
		return nil
	})
	return out, err
}

// PullsForCommit — PR, с которыми связан коммит (GET /repos/{r}/commits/{sha}/pulls).
func (c *Client) PullsForCommit(ctx context.Context, repo, sha string) ([]PR, error) {
	if err := checkRepo(repo); err != nil {
		return nil, err
	}
	if !shaRe.MatchString(sha) {
		return nil, fmt.Errorf("github: некорректный sha %q", sha)
	}
	var out []PR
	err := c.pages(ctx, fmt.Sprintf("/repos/%s/commits/%s/pulls", repo, sha), func(b []byte) error {
		var page []struct {
			Number         int     `json:"number"`
			User           apiUser `json:"user"`
			MergedAt       *string `json:"merged_at"`
			MergeCommitSHA *string `json:"merge_commit_sha"`
			Head           struct {
				SHA string `json:"sha"`
			} `json:"head"`
			Base struct {
				Ref string `json:"ref"`
			} `json:"base"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return err
		}
		for _, p := range page {
			pr := PR{Number: p.Number, Author: p.User.Login, HeadSHA: p.Head.SHA, BaseRef: p.Base.Ref, Merged: p.MergedAt != nil}
			if p.MergeCommitSHA != nil {
				pr.MergeCommitSHA = *p.MergeCommitSHA
			}
			out = append(out, pr)
		}
		return nil
	})
	return out, err
}
