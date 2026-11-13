package cs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Les fichiers de testdata/ sont des copies des scripts community-scripts/ProxmoxVE (licence MIT).
func load(t *testing.T, name string) Script {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".sh")
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(string(b))
}

func TestTermix(t *testing.T) {
	s := load(t, "termix")
	if s.NeedCPU != 4 || s.NeedRAMMB != 4096 {
		t.Errorf("ressources : %d CPU, %d Mo", s.NeedCPU, s.NeedRAMMB)
	}
	if len(s.Apps) != 2 {
		t.Fatalf("2 applis attendues (guacd, termix) : %+v", s.Apps)
	}
	g, x := s.Apps[0], s.Apps[1]
	if g.Name != "guacd" || g.Kind != "tag" || g.Repo != "apache/guacamole-server" || g.Forge != "github" {
		t.Errorf("guacd : %+v", g)
	}
	if x.Name != "termix" || x.Kind != "release" || x.Repo != "Termix-SSH/Termix" || x.VersionFile() != "termix" {
		t.Errorf("termix : %+v", x)
	}
	if len(s.Prompts) != 1 || !strings.Contains(s.Prompts[0], "Update Nginx configuration?") {
		t.Errorf("question interactive non repérée : %q", s.Prompts)
	}
	if s.OSOnly {
		t.Error("termix met à jour son appli")
	}
}

func TestOSOnlyScripts(t *testing.T) {
	for _, n := range []string{"debian", "forgejo"} {
		s := load(t, n)
		if !s.OSOnly || len(s.Apps) != 0 {
			t.Errorf("%s : seulement l'OS attendu : %+v", n, s)
		}
	}
	if s := load(t, "n8n"); s.OSOnly {
		t.Error("n8n met à jour son appli via npm")
	}
}

func TestPinnedPrefixAndBranch(t *testing.T) {
	im := load(t, "immich")
	var immich *App
	for i := range im.Apps {
		if im.Apps[i].Name == "Immich" {
			immich = &im.Apps[i]
		}
	}
	if immich == nil || immich.Pinned == "" || !strings.HasPrefix(immich.Pinned, "v") || immich.VersionFile() != "immich" {
		t.Errorf("version épinglée d'Immich non résolue : %+v", immich)
	}
	st := load(t, "storyteller")
	if len(st.Apps) == 0 || st.Apps[0].Forge != "gitlab" || st.Apps[0].Prefix != "web-v2" {
		t.Errorf("storyteller (gitlab, préfixe) : %+v", st.Apps)
	}
	sx := load(t, "vane")
	if len(sx.Apps) != 2 || sx.Apps[1].Name != "searxng" || sx.Apps[1].Kind != "branch" || sx.Apps[1].Branch != "master" || sx.Apps[1].Pinned != "" {
		t.Errorf("vane (searxng suivi par branche) : %+v", sx.Apps)
	}
}

func TestSemaphorePrompt(t *testing.T) {
	s := load(t, "semaphore")
	if len(s.Prompts) == 0 {
		t.Error("la question de migration de Semaphore doit être repérée")
	}
}

func TestFetcherAllowListAndCache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/ProxmoxVE/main/ct/termix.sh" {
			http.NotFound(w, r)
			return
		}
		b, _ := os.ReadFile("testdata/termix.sh")
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	base := srv.URL + "/ProxmoxVE/main"
	f := NewFetcher([]string{base + "/"}, time.Hour, srv.Client())

	if _, err := f.Get(context.Background(), "https://malveillant.example/x", "termix"); !errors.Is(err, ErrBaseNotAllowed) {
		t.Errorf("base non autorisée acceptée : %v", err)
	}
	if _, err := f.Get(context.Background(), base, "../../etc/passwd"); err == nil {
		t.Error("nom de script invalide accepté")
	}
	s, err := f.Get(context.Background(), base, "termix")
	if err != nil || len(s.Apps) != 2 || s.URL != base+"/ct/termix.sh" {
		t.Fatalf("lecture : %v %+v", err, s)
	}
	_, _ = f.Get(context.Background(), base, "termix")
	if hits != 1 {
		t.Errorf("le cache doit éviter un second téléchargement (%d requêtes)", hits)
	}
	if _, err := f.Get(context.Background(), base, "absent"); err == nil || !strings.Contains(err.Error(), "introuvable") {
		t.Errorf("404 : %v", err)
	}
}
