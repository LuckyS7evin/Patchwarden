package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"golang.org/x/crypto/bcrypt"
)

// fakeEngine soumet de vraies tâches au gestionnaire, avec un travail simulé.
type fakeEngine struct {
	jm      *jobs.Manager
	release chan struct{}
}

func (f *fakeEngine) CanDetect(g inventory.Guest) error {
	if g.Type != "lxc" || g.Status != "running" {
		return errors.New("non éligible")
	}
	return nil
}

func (f *fakeEngine) Detect(g inventory.Guest, user string) (jobs.Job, error) {
	if err := f.CanDetect(g); err != nil {
		return jobs.Job{}, err
	}
	t := jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
	return f.jm.Submit(jobs.KindDetect, t, false, user, func(_ context.Context, _ jobs.Job, log jobs.Logger) (string, error) {
		log(false, "pw.detect=1")
		if f.release != nil {
			<-f.release
		}
		log(true, "<b>avertissement</b>")
		return "2 paquet(s) dont 1 de sécurité", nil
	})
}

func (f *fakeEngine) DetectAll(gs []inventory.Guest, user string) (int, int) {
	var a, b int
	for _, g := range gs {
		if _, err := f.Detect(g, user); err != nil {
			b++
		} else {
			a++
		}
	}
	return a, b
}

type fakeInv struct {
	snap      inventory.Snapshot
	triggered int
}

func (f *fakeInv) Current() (inventory.Snapshot, bool) { return f.snap, false }
func (f *fakeInv) TriggerRefresh()                     { f.triggered++ }

type harness struct {
	t     *testing.T
	srv   *Server
	ts    *httptest.Server
	c     *http.Client
	inv   *fakeInv
	now   time.Time
	jm    *jobs.Manager
	eng   *fakeEngine
	store *detect.Store
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("bon-mot-de-passe"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Auth: config.Auth{Username: "admin", PasswordHash: string(hash)}}
	cfg.Auth.SessionDuration.Duration = time.Hour
	inv := &fakeInv{snap: inventory.Snapshot{
		FetchedAt: time.Date(2026, 11, 13, 18, 0, 0, 0, time.UTC),
		Errors:    map[string]string{"odin": "délai dépassé"},
		Guests: []inventory.Guest{
			{Node: "loki", Type: "lxc", VMID: 104, Name: "termix", Status: "running", Tags: []string{"community-script"}, CommunityScript: true},
			{Node: "loki", Type: "qemu", VMID: 203, Name: "PBS", Status: "running", Tags: []string{"critique"}, Critical: true, CriticalReason: "tag « critique »"},
			{Node: "tyr", Type: "qemu", VMID: 999, Name: "<script>alert(1)</script>", Status: "stopped"},
			{Node: "tyr", Type: "lxc", VMID: 114, Status: "unknown"},
		},
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	jm, err := jobs.New(dir, 2, 100, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jm.Close)
	store, _ := detect.OpenStore(dir)
	eng := &fakeEngine{jm: jm}
	srv, err := New(cfg, inv, Deps{Engine: eng, Jobs: jm, Detections: store}, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: srv, inv: inv, now: time.Date(2026, 11, 13, 18, 5, 0, 0, time.UTC), jm: jm, eng: eng, store: store}
	srv.now = func() time.Time { return h.now }
	h.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(h.ts.Close)
	jar, _ := cookiejar.New(nil)
	h.c = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

func (h *harness) do(method, path string, form url.Values, hdr map[string]string) (*http.Response, string) {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (h *harness) login() {
	h.t.Helper()
	resp, _ := h.do("POST", "/connexion", url.Values{"username": {"admin"}, "password": {"bon-mot-de-passe"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		h.t.Fatalf("connexion : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) csrf() string {
	_, body := h.do("GET", "/", nil, nil)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("jeton CSRF introuvable")
	}
	return m[1]
}

func TestUnauthenticatedIsRedirected(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do("GET", "/", nil, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/connexion" {
		t.Errorf("redirection attendue : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = h.do("POST", "/inventaire/rafraichir", url.Values{}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST non authentifié : %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/sante", nil, nil); resp.StatusCode != 200 {
		t.Errorf("/sante : %d", resp.StatusCode)
	}
}

func TestLoginAndInventoryPage(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, body := h.do("GET", "/", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("inventaire : %d", resp.StatusCode)
	}
	for _, want := range []string{"termix", "community-scripts", "confirmation renforcée", "tag « critique »", "il y a 5 min", "odin : délai dépassé", "&lt;script&gt;", "(nom indisponible)", ">inconnu<", "pvestatd sur tyr"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q absent de la page", want)
		}
	}
	if strings.Contains(body, "<script>alert") {
		t.Error("nom d'invité non échappé")
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP : %q", csp)
	}
	for _, c := range h.c.Jar.Cookies(mustURL(h.ts.URL)) {
		if c.Name == sessionCookie && c.Value == "" {
			t.Error("cookie de session vide")
		}
	}
}

func TestFilter(t *testing.T) {
	h := newHarness(t)
	h.login()
	_, body := h.do("GET", "/?type=lxc", nil, nil)
	if !strings.Contains(body, "termix") || strings.Contains(body, ">PBS<") {
		t.Error("filtre par type inopérant")
	}
	_, body = h.do("GET", "/?q=203", nil, nil)
	if !strings.Contains(body, ">PBS<") || strings.Contains(body, ">termix<") {
		t.Error("recherche par ID inopérante")
	}
}

func TestBadPasswordAndThrottle(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 5; i++ {
		resp, body := h.do("POST", "/connexion", url.Values{"username": {"admin"}, "password": {"faux"}}, nil)
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "incorrect") {
			t.Fatalf("essai %d : %d", i, resp.StatusCode)
		}
	}
	resp, body := h.do("POST", "/connexion", url.Values{"username": {"admin"}, "password": {"bon-mot-de-passe"}}, nil)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "Trop d") {
		t.Fatalf("blocage attendu après 5 échecs : %d", resp.StatusCode)
	}
	h.now = h.now.Add(16 * time.Minute)
	h.login()
}

func TestCSRFAndOrigin(t *testing.T) {
	h := newHarness(t)
	h.login()
	if resp, _ := h.do("POST", "/inventaire/rafraichir", url.Values{"csrf": {"faux"}}, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("jeton CSRF faux accepté : %d", resp.StatusCode)
	}
	tok := h.csrf()
	if resp, _ := h.do("POST", "/inventaire/rafraichir", url.Values{"csrf": {tok}}, map[string]string{"Origin": "https://malveillant.example"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("origine étrangère acceptée : %d", resp.StatusCode)
	}
	if h.inv.triggered != 0 {
		t.Fatal("rafraîchissement déclenché malgré le refus")
	}
	resp, _ := h.do("POST", "/inventaire/rafraichir?type=lxc", url.Values{"csrf": {tok}}, map[string]string{"Origin": h.ts.URL})
	if resp.StatusCode != http.StatusSeeOther || h.inv.triggered != 1 || resp.Header.Get("Location") != "/?type=lxc" {
		t.Errorf("rafraîchissement légitime : %d, déclenché %d, %s", resp.StatusCode, h.inv.triggered, resp.Header.Get("Location"))
	}
}

func TestSessionExpiryAndLogout(t *testing.T) {
	h := newHarness(t)
	h.login()
	tok := h.csrf()
	resp, _ := h.do("POST", "/deconnexion", url.Values{"csrf": {tok}}, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("déconnexion : %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/", nil, nil); resp.StatusCode != http.StatusSeeOther {
		t.Error("session encore valide après déconnexion")
	}
	h.login()
	h.now = h.now.Add(2 * time.Hour)
	if resp, _ := h.do("GET", "/", nil, nil); resp.StatusCode != http.StatusSeeOther {
		t.Error("session encore valide après expiration")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func (h *harness) waitJob(id string) jobs.Job {
	h.t.Helper()
	for i := 0; i < 300; i++ {
		if j, _ := h.jm.Get(id); j.Status.Finished() {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("tâche non terminée")
	return jobs.Job{}
}

func TestDetectFlow(t *testing.T) {
	h := newHarness(t)
	h.login()
	tok := h.csrf()
	if resp, _ := h.do("POST", "/invites/loki/104/detecter", url.Values{}, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("détection sans jeton CSRF : %d", resp.StatusCode)
	}
	resp, _ := h.do("POST", "/invites/loki/104/detecter", url.Values{"csrf": {tok}}, nil)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/taches/") {
		t.Fatalf("redirection vers la tâche attendue : %d %s", resp.StatusCode, loc)
	}
	id := strings.TrimPrefix(loc, "/taches/")
	j := h.waitJob(id)
	if j.RequestedBy != "admin" || j.Target.Name != "termix" {
		t.Errorf("tâche : %+v", j)
	}
	_, body := h.do("GET", loc, nil, nil)
	for _, want := range []string{"réussie", "2 paquet(s) dont 1 de sécurité", "pw.detect=1", "&lt;b&gt;avertissement&lt;/b&gt;", `class="err"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page de tâche sans %q", want)
		}
	}
	if strings.Contains(body, "tache.js") {
		t.Error("une tâche terminée ne doit pas charger le suivi en direct")
	}
	_, body = h.do("GET", "/taches", nil, nil)
	if !strings.Contains(body, "termix") || !strings.Contains(body, id) {
		t.Error("historique incomplet")
	}
	// VM : refusée avec un message, aucune tâche créée.
	resp, _ = h.do("POST", "/invites/loki/203/detecter", url.Values{"csrf": {tok}}, nil)
	if !strings.Contains(resp.Header.Get("Location"), "erreur=") {
		t.Errorf("refus attendu pour une VM : %s", resp.Header.Get("Location"))
	}
	if n := len(h.jm.List("", 0)); n != 1 {
		t.Errorf("%d tâches, 1 attendue", n)
	}
}

func TestDetectAll(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, _ := h.do("POST", "/inventaire/detecter", url.Values{"csrf": {h.csrf()}}, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/taches?lancees=1&ignores=3" {
		t.Errorf("détection globale : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLiveStream(t *testing.T) {
	h := newHarness(t)
	h.eng.release = make(chan struct{})
	h.login()
	j, err := h.eng.Detect(h.inv.snap.Guests[0], "admin")
	if err != nil {
		t.Fatal(err)
	}
	// Une seconde demande pendant l'exécution renvoie vers la tâche en cours.
	resp, _ := h.do("POST", "/invites/loki/104/detecter", url.Values{"csrf": {h.csrf()}}, nil)
	if resp.Header.Get("Location") != "/taches/"+j.ID {
		t.Errorf("tâche en cours non réutilisée : %s", resp.Header.Get("Location"))
	}
	_, page := h.do("GET", "/taches/"+j.ID, nil, nil)
	if !strings.Contains(page, `data-flux="/taches/`+j.ID+`/flux"`) || !strings.Contains(page, "tache.js") {
		t.Error("suivi en direct absent de la page")
	}
	go func() { time.Sleep(100 * time.Millisecond); close(h.eng.release) }()
	_, stream := h.do("GET", "/taches/"+j.ID+"/flux", nil, nil)
	for _, want := range []string{"event: debut", `"x":"pw.detect=1"`, `"e":true`, "event: fin", "réussie"} {
		if !strings.Contains(stream, want) {
			t.Errorf("flux sans %q :\n%s", want, stream)
		}
	}
	if i, k := strings.Index(stream, "pw.detect=1"), strings.Index(stream, "avertissement"); i < 0 || k < i {
		t.Error("ordre des lignes incorrect")
	}
}

func TestGuestPage(t *testing.T) {
	h := newHarness(t)
	h.login()
	_ = h.store.Put("loki/104", detect.Result{
		At: h.now.Add(-10 * time.Minute), JobID: "20261113-180000-aaaaaa", OSPretty: "Debian GNU/Linux 13 (trixie)",
		Nproc: 2, MemMB: 2048, RootUsedPct: 78,
		CS: detect.CS{Entry: "legacy", Script: "termix", BaseAllowed: true, NeedCPU: 4, NeedRAMMB: 4096,
			Prompts: []string{"Update Nginx configuration? [Y/n]:"}, PageURL: "https://community-scripts.org/scripts/termix"},
		Apt: detect.Apt{Present: true, SecurityRepo: true, Total: 3, Security: 2, SecurityStrict: 1, IndexAgeHours: 0,
			Packages: []detect.Package{{Name: "libssl3t64", Old: "3.5.7-1", New: "3.5.7-2", Security: true}, {Name: "base-files", Old: "13.8", New: "13.9"}}},
		Apps: []detect.App{{Name: "termix", Repo: "Termix-SSH/Termix", Installed: "release-2.6.1-tag", InstalledKnown: true, Latest: "v26.11.1",
			ChangelogURL: "https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"}},
	})
	_, body := h.do("GET", "/invites/loki/104", nil, nil)
	for _, want := range []string{"Debian GNU/Linux 13", "ancien format", "augmentation temporaire", "Update Nginx configuration?",
		"release-2.6.1-tag", "v26.11.1", `href="https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"`,
		"mise à jour disponible", "80 %", "1 correctif(s) de sécurité ne passent pas seuls", "libssl3t64", "il y a 10 min"} {
		if !strings.Contains(body, want) {
			t.Errorf("page invité sans %q", want)
		}
	}
	_, inv := h.do("GET", "/", nil, nil)
	for _, want := range []string{"3 apt · 2 sécu", "termix → v26.11.1", "Détecter les mises à jour (1 LXC)"} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventaire sans %q", want)
		}
	}
	if resp, _ := h.do("GET", "/invites/loki/9999", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("invité inconnu : %d", resp.StatusCode)
	}
}
