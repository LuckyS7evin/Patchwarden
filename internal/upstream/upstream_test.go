package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeForge(t *testing.T) (*Client, *int32) {
	t.Helper()
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/gh/repos/Termix-SSH/Termix/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get("Authorization") != "Bearer jeton" {
			t.Errorf("jeton GitHub absent : %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"tag_name":"v26.11.1","html_url":"https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"}`))
	})
	mux.HandleFunc("/gh/repos/apache/guacamole-server/tags", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"1.6.0"},{"name":"1.10.0-RC1"},{"name":"1.5.5"},{"name":"1.6.1"}]`))
	})
	mux.HandleFunc("/gh/repos/Listenarrs/Listenarr/releases", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0-beta.1","prerelease":true},{"tag_name":"v1.9.0"}]`))
	})
	mux.HandleFunc("/gh/repos/limite/atteinte/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/cb/repos/forgejo/forgejo/releases", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v14.0.0-rc1","prerelease":true},{"tag_name":"v13.0.2","html_url":"https://codeberg.org/forgejo/forgejo/releases/tag/v13.0.2"}]`))
	})
	mux.HandleFunc("/gl/projects/storyteller-platform%2Fstoryteller/releases", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"mobile-v3.0.0"},{"tag_name":"web-v2.4.1"},{"tag_name":"web-v2.4.0"}]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New("jeton", time.Hour, srv.Client())
	c.GitHubAPI, c.CodebergAPI, c.GitLabAPI = srv.URL+"/gh", srv.URL+"/cb", srv.URL+"/gl"
	return c, &hits
}

func TestForges(t *testing.T) {
	c, hits := fakeForge(t)
	ctx := context.Background()
	for _, tc := range []struct {
		q       Query
		tag, cl string
	}{
		{Query{Forge: "github", Repo: "Termix-SSH/Termix", Kind: "release"}, "v26.11.1", "https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"},
		{Query{Forge: "github", Repo: "apache/guacamole-server", Kind: "tag"}, "1.6.1", "https://github.com/apache/guacamole-server/releases/tag/1.6.1"},
		{Query{Forge: "github", Repo: "Listenarrs/Listenarr", Kind: "release", Pre: true}, "v2.0.0-beta.1", ""},
		{Query{Forge: "codeberg", Repo: "forgejo/forgejo", Kind: "release"}, "v13.0.2", "https://codeberg.org/forgejo/forgejo/releases/tag/v13.0.2"},
		{Query{Forge: "gitlab", Repo: "storyteller-platform/storyteller", Kind: "release", Prefix: "web-v2"}, "web-v2.4.1", "https://gitlab.com/storyteller-platform/storyteller/-/releases/web-v2.4.1"},
	} {
		r, err := c.Latest(ctx, tc.q)
		if err != nil {
			t.Errorf("%s : %v", tc.q.Repo, err)
			continue
		}
		if r.Tag != tc.tag || (tc.cl != "" && r.ChangelogURL != tc.cl) {
			t.Errorf("%s : %+v", tc.q.Repo, r)
		}
	}
	q := Query{Forge: "github", Repo: "Termix-SSH/Termix", Kind: "release"}
	_, _ = c.Latest(ctx, q)
	if *hits != 1 {
		t.Errorf("cache inopérant : %d requêtes", *hits)
	}
}

func TestErrors(t *testing.T) {
	c, _ := fakeForge(t)
	ctx := context.Background()
	if _, err := c.Latest(ctx, Query{Forge: "github", Repo: "limite/atteinte", Kind: "release"}); err == nil || !strings.Contains(err.Error(), "github_token") {
		t.Errorf("limite d'API : %v", err)
	}
	if _, err := c.Latest(ctx, Query{Forge: "github", Repo: "absent/depot", Kind: "release"}); err == nil || !strings.Contains(err.Error(), "introuvable") {
		t.Errorf("404 : %v", err)
	}
	if _, err := c.Latest(ctx, Query{Forge: "github", Repo: "../etc", Kind: "release"}); err == nil {
		t.Error("dépôt invalide accepté")
	}
}

func TestVersionOrder(t *testing.T) {
	got, _ := pickTag([]string{"v1.9.0", "v1.10.0", "v1.2.0", "v2.0.0-rc1"}, Query{})
	if got != "v1.10.0" {
		t.Errorf("tri numérique : %s", got)
	}
}
