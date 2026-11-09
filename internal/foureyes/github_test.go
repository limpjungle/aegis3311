package foureyes

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientPaginationAndHeaders(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" ||
			r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("заголовки: %v", r.Header)
		}
		if r.URL.Query().Get("per_page") != "100" {
			t.Errorf("per_page: %s", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=2>; rel="next", <%s/last>; rel="last"`, srv.URL, r.URL.Path, srv.URL))
			fmt.Fprint(w, `[{"id":1,"user":{"login":"a","type":"User"},"state":"APPROVED","commit_id":"x"}]`)
		default:
			fmt.Fprint(w, `[{"id":2,"user":{"login":"b","type":"Bot"},"state":"COMMENTED","commit_id":"y"}]`)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "tok"}
	rv, err := c.Reviews(context.Background(), "o/r", 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(rv) != 2 || rv[0].Login != "a" || rv[1].UserType != "Bot" || rv[1].State != "COMMENTED" {
		t.Errorf("ревью: %+v", rv)
	}
}

func TestClientPageLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s%s?page=9>; rel="next"`, srv.URL, r.URL.Path))
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Files(context.Background(), "o/r", 1)
	if err == nil || !strings.Contains(err.Error(), "страниц") {
		t.Errorf("ожидалась ошибка лимита страниц, получено %v", err)
	}
}

func TestClientErrors(t *testing.T) {
	for _, code := range []int{404, 500, 403} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		_, err := (&Client{BaseURL: srv.URL}).Pull(context.Background(), "o/r", 1)
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Errorf("код %d: ошибка %v", code, err)
		}
	}
}

func TestClientBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"x":"`))
		w.Write([]byte(strings.Repeat("a", maxBodyBytes+10)))
	}))
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).Pull(context.Background(), "o/r", 1); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Errorf("ожидалась ошибка лимита тела, получено %v", err)
	}
}

func TestClientRejectsForeignLinkHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/x?page=2>; rel="next"`)
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).Commits(context.Background(), "o/r", 1); err == nil {
		t.Error("ссылка на другой хост должна быть ошибкой")
	}
}

func TestClientParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/pulls/3"):
			fmt.Fprint(w, `{"number":3,"user":{"login":"zed"},"merged":true,"merge_commit_sha":"`+strings.Repeat("a", 40)+`","head":{"sha":"h"},"base":{"ref":"main"}}`)
		case strings.HasSuffix(r.URL.Path, "/commits"):
			fmt.Fprint(w, `[{"author":{"login":"zed"},"committer":null},{"author":null,"committer":{"login":"web"}}]`)
		case strings.HasSuffix(r.URL.Path, "/files"):
			fmt.Fprint(w, `[{"filename":"b","previous_filename":"a"},{"filename":"c"}]`)
		case strings.Contains(r.URL.Path, "/commits/") && strings.HasSuffix(r.URL.Path, "/pulls"):
			fmt.Fprint(w, `[{"number":3,"user":{"login":"zed"},"merged_at":"2026-01-01T00:00:00Z","merge_commit_sha":"`+strings.Repeat("a", 40)+`","head":{"sha":"h"},"base":{"ref":"main"}},
			{"number":4,"user":{"login":"y"},"merged_at":null,"merge_commit_sha":null,"head":{"sha":"g"},"base":{"ref":"main"}}]`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	ctx := context.Background()
	pr, err := c.Pull(ctx, "o/r", 3)
	if err != nil || pr.Author != "zed" || !pr.Merged || pr.HeadSHA != "h" || pr.BaseRef != "main" {
		t.Errorf("pull: %+v %v", pr, err)
	}
	cm, err := c.Commits(ctx, "o/r", 3)
	if err != nil || len(cm) != 2 || cm[0].Author != "zed" || cm[1].Committer != "web" {
		t.Errorf("commits: %+v %v", cm, err)
	}
	fl, err := c.Files(ctx, "o/r", 3)
	if err != nil || strings.Join(fl, ",") != "b,a,c" {
		t.Errorf("files: %v %v", fl, err)
	}
	ps, err := c.PullsForCommit(ctx, "o/r", strings.Repeat("a", 40))
	if err != nil || len(ps) != 2 || !ps[0].Merged || ps[1].Merged {
		t.Errorf("pulls: %+v %v", ps, err)
	}
	if _, err := c.PullsForCommit(ctx, "o/r", "xyz"); err == nil {
		t.Error("некорректный sha должен быть ошибкой")
	}
	if _, err := c.Pull(ctx, "bad repo", 1); err == nil {
		t.Error("некорректный репозиторий должен быть ошибкой")
	}
}

func TestClientTooManyCommits(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var items []string
		n := 100
		if r.URL.Query().Get("page") == "3" {
			n = 50
		} else {
			next := "2"
			if r.URL.Query().Get("page") == "2" {
				next = "3"
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&page=%s>; rel="next"`, srv.URL, r.URL.Path, next))
		}
		for i := 0; i < n; i++ {
			items = append(items, `{"author":{"login":"a"},"committer":{"login":"a"}}`)
		}
		fmt.Fprint(w, "["+strings.Join(items, ",")+"]")
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Commits(context.Background(), "o/r", 1)
	if err != ErrTooManyCommits {
		t.Errorf("250 коммитов: ожидалась ErrTooManyCommits, получено %v", err)
	}
}
