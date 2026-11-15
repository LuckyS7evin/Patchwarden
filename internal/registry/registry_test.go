package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := map[string]string{
		"nginx":                              "docker.io/library/nginx:latest",
		"nginx:1.27-alpine":                  "docker.io/library/nginx:1.27-alpine",
		"amir20/dozzle:v8":                   "docker.io/amir20/dozzle:v8",
		"ghcr.io/mealie-recipes/mealie:v1.8": "ghcr.io/mealie-recipes/mealie:v1.8",
		"lscr.io/linuxserver/lms:stable":     "lscr.io/linuxserver/lms:stable",
		"localhost:5000/app":                 "localhost:5000/app:latest",
		"index.docker.io/library/redis:7":    "docker.io/library/redis:7",
		"nginx@sha256:abc":                   "docker.io/library/nginx@sha256:abc",
	}
	for in, want := range cases {
		r, err := Parse(in)
		if err != nil || r.String() != want {
			t.Errorf("%s : %v %v, attendu %s", in, r, err, want)
		}
	}
	if _, err := Parse("Bad/Name"); err == nil {
		t.Error("majuscules acceptées")
	}
	if r, _ := Parse("nginx"); r.Short() != "nginx" {
		t.Errorf("Short : %s", r.Short())
	}
}

func TestNewer(t *testing.T) {
	tags := []string{"latest", "v1.8.0", "v1.9.0", "v1.12.2", "v2.0.0-rc1", "1.9.9", "v1.12.2-alpine", "5", "6", "7-beta", "5.1", "20240101", "3.12-alpine", "3.13-alpine", "3.14", "1.2.3-ls45", "1.2.3-ls47", "1.2.4-ls50"}
	cases := map[string]string{
		"v1.8.0":      "v1.12.2",
		"v1.12.2":     "",
		"5":           "6",
		"latest":      "",
		"3.12-alpine": "3.13-alpine",
		"1.2.3-ls45":  "1.2.4-ls50",
		"stable":      "",
	}
	for cur, want := range cases {
		if got := Newer(cur, tags); got != want {
			t.Errorf("Newer(%s) = %q, attendu %q", cur, got, want)
		}
	}
}

func TestChangelogURL(t *testing.T) {
	r := func(s string) Ref { x, _ := Parse(s); return x }
	cases := []struct{ img, src, want string }{
		{"ghcr.io/mealie-recipes/mealie:v1.8.0", "", "https://github.com/mealie-recipes/mealie/releases"},
		{"lscr.io/linuxserver/lms:stable", "", "https://github.com/linuxserver/docker-lms/releases"},
		{"amir20/dozzle:latest", "https://github.com/amir20/dozzle", "https://github.com/amir20/dozzle/releases"},
		{"jasongdove/ersatztv:latest", "https://github.com/ErsatzTV/ErsatzTV-ffmpeg", "https://hub.docker.com/r/jasongdove/ersatztv/tags"},
		{"nginx:1.27", "", "https://hub.docker.com/_/nginx/tags"},
		{"quay.io/x/y:1", "", "https://quay.io/repository/x/y?tab=tags"},
	}
	for _, c := range cases {
		if got := ChangelogURL(r(c.img), c.src); got != c.want {
			t.Errorf("%s : %s, attendu %s", c.img, got, c.want)
		}
	}
}

// Registre factice : exige un jeton anonyme (comme Docker Hub et ghcr.io).
func fakeRegistry(t *testing.T) (*httptest.Server, *int32) {
	var heads int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:library/nginx:pull" {
				http.Error(w, "scope", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token":"t0k","expires_in":300}`))
			return
		case r.Header.Get("Authorization") != "Bearer t0k":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.test",scope="repository:library/nginx:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		case r.URL.Path == "/v2/library/nginx/manifests/1.27" && r.Method == http.MethodHead:
			atomic.AddInt32(&heads, 1)
			if !strings.Contains(r.Header.Get("Accept"), "image.index") {
				http.Error(w, "accept", http.StatusBadRequest)
				return
			}
			w.Header().Set("Docker-Content-Digest", "sha256:remote")
		case r.URL.Path == "/v2/library/nginx/tags/list":
			if r.URL.Query().Get("last") == "" {
				w.Header().Set("Link", `</v2/library/nginx/tags/list?n=1000&last=1.27>; rel="next"`)
				_, _ = w.Write([]byte(`{"tags":["1.26","1.27"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"tags":["1.28","1.29-rc1"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &heads
}

func TestDigestAndTags(t *testing.T) {
	srv, heads := fakeRegistry(t)
	defer srv.Close()
	c := New(time.Hour, srv.Client())
	c.Scheme = "http"
	c.Hosts = map[string]string{"docker.io": strings.TrimPrefix(srv.URL, "http://")}
	ref, _ := Parse("nginx:1.27")
	ctx := context.Background()
	d, err := c.Digest(ctx, ref)
	if err != nil || d != "sha256:remote" {
		t.Fatalf("digest : %q %v", d, err)
	}
	if _, err := c.Digest(ctx, ref); err != nil || atomic.LoadInt32(heads) != 1 {
		t.Errorf("cache non utilisé : %d requêtes", atomic.LoadInt32(heads))
	}
	tags, err := c.Tags(ctx, ref)
	if err != nil || len(tags) != 4 {
		t.Fatalf("tags : %v %v", tags, err)
	}
	if n := Newer("1.27", tags); n != "1.28" {
		t.Errorf("Newer : %s", n)
	}
	other, _ := Parse("nginx:absent")
	if _, err := c.Digest(ctx, other); err != ErrPrivate {
		t.Errorf("tag absent : %v", err)
	}
}
