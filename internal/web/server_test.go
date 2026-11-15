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
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"golang.org/x/crypto/bcrypt"
)

// fakeEngine soumet de vraies tâches au gestionnaire, avec un travail simulé.
type fakeEngine struct {
	jm       *jobs.Manager
	release  chan struct{}
	answers  map[string]map[string]string
	prefs    map[string]string
	lastSnap *bool
	rolled   string
	// Lots et redémarrages.
	restarted           []string
	batch               []engine.BatchRequest
	batchDry, batchStop bool
	batches             []engine.Batch
}

func (f *fakeEngine) PlanFor(g inventory.Guest, a engine.Action) engine.Plan {
	p := engine.Plan{Action: a, Guest: g, NeedName: g.Critical, Steps: []string{"apt-get update", "apt-get --with-new-pkgs upgrade : 3 paquet(s)"}}
	if a == engine.ActFull && g.CommunityScript {
		saved := f.answers[g.Key()]
		v, ok := saved[nginxQ]
		p.CSRun = true
		p.Answers = []engine.PromptAnswer{{Prompt: nginxQ, Value: v, Set: ok}}
		if !ok {
			p.Blockers = []string{"le script pose des questions sans terminal : enregistrez une réponse pour chacune (page de l'invité)"}
		}
	}
	p.Snap = engine.SnapPlan{Possible: true, Checked: g.Critical, Reason: "décochée par défaut", Name: "pw-20261113-1805-" + string(a), Storage: "local-lvm (lvmthin) : 45 %"}
	if g.Critical {
		p.Snap.Reason = "invité critique"
	}
	if g.Type == "qemu" {
		p.Snap = engine.SnapPlan{Why: "le stockage de ce CT ne permet pas les snapshots (local : dir)"}
	}
	return p
}

func (f *fakeEngine) CanSnapAction(g inventory.Guest) error {
	if g.Type != "lxc" {
		return errors.New("snapshots des VM : prochain jalon")
	}
	return nil
}

func (f *fakeEngine) Rollback(g inventory.Guest, name, user, typed string) (jobs.Job, error) {
	if typed != g.Name {
		return jobs.Job{}, engine.ErrConfirm
	}
	f.rolled = name
	t := jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
	return f.jm.Submit(jobs.KindRollback, t, false, user, func(context.Context, jobs.Job, jobs.Logger) (string, error) { return "ok", nil })
}

func (f *fakeEngine) DeleteSnapshot(g inventory.Guest, name, user string, confirmed bool) (jobs.Job, error) {
	if !confirmed {
		return jobs.Job{}, engine.ErrConfirm
	}
	t := jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
	return f.jm.Submit(jobs.KindSnapDelete, t, false, user, func(context.Context, jobs.Job, jobs.Logger) (string, error) { return "ok", nil })
}

func (f *fakeEngine) SnapPref(key string) string { return f.prefs[key] }

func (f *fakeEngine) SetSnapPref(key, v string) error {
	if v != "" && v != engine.PrefAlways && v != engine.PrefNever {
		return errors.New("réglage inconnu")
	}
	if f.prefs == nil {
		f.prefs = map[string]string{}
	}
	f.prefs[key] = v
	return nil
}

func (f *fakeEngine) SnapDefaults() engine.SnapConfig { return engine.SnapConfig{Keep: 1, MaxPct: 90} }

func (f *fakeEngine) PlanRestart(g inventory.Guest) engine.RestartPlan {
	p := engine.RestartPlan{Guest: g, NeedName: g.Critical}
	if g.Type != "lxc" || g.Status != "running" {
		p.Why = "non éligible"
		return p
	}
	p.Units, p.Reboot = []string{"nginx.service"}, true
	return p
}

func (f *fakeEngine) RestartServices(g inventory.Guest, user string, confirmed bool) (jobs.Job, error) {
	if !confirmed {
		return jobs.Job{}, engine.ErrConfirm
	}
	f.restarted = append(f.restarted, "services:"+g.Key())
	t := jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
	return f.jm.Submit(jobs.KindServices, t, false, user, func(context.Context, jobs.Job, jobs.Logger) (string, error) { return "ok", nil })
}

func (f *fakeEngine) Reboot(g inventory.Guest, user string, confirmed bool, typed string) (jobs.Job, error) {
	if !confirmed || (g.Critical && typed != g.Name) {
		return jobs.Job{}, engine.ErrConfirm
	}
	f.restarted = append(f.restarted, "ct:"+g.Key())
	t := jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
	return f.jm.Submit(jobs.KindReboot, t, false, user, func(context.Context, jobs.Job, jobs.Logger) (string, error) { return "ok", nil })
}

func (f *fakeEngine) PreviewBatch(reqs []engine.BatchRequest) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		if r.Guest.Critical {
			out[i] = "invité à confirmation renforcée"
		}
	}
	return out
}

func (f *fakeEngine) StartBatch(reqs []engine.BatchRequest, dry, stop bool, user string) (engine.Batch, error) {
	if len(reqs) == 0 {
		return engine.Batch{}, engine.ErrEmptyBatch
	}
	f.batch = reqs
	f.batchDry, f.batchStop = dry, stop
	b := engine.Batch{ID: "lot-test", By: user, DryRun: dry, StopOnFail: stop, Status: engine.BatchDone, CreatedAt: time.Now()}
	for _, r := range reqs {
		b.Items = append(b.Items, engine.BatchItem{Node: r.Guest.Node, VMID: r.Guest.VMID, Name: r.Guest.Name, Op: r.Op, Snapshot: r.Snapshot, Status: engine.ItemSuccess})
	}
	f.batches = append(f.batches, b)
	return b, nil
}

func (f *fakeEngine) Get(id string) (engine.Batch, bool) {
	for _, b := range f.batches {
		if b.ID == id {
			return b, true
		}
	}
	return engine.Batch{}, false
}

func (f *fakeEngine) List(int) []engine.Batch { return f.batches }

func (f *fakeEngine) Execute(g inventory.Guest, a engine.Action, dry bool, user string, confirmed bool, name string, snapshot bool) (jobs.Job, error) {
	f.lastSnap = &snapshot
	p := f.PlanFor(g, a)
	if !p.OK() {
		return jobs.Job{}, errors.New(p.Blockers[0])
	}
	if !dry && (!confirmed || (p.NeedName && name != g.Name)) {
		return jobs.Job{}, engine.ErrConfirm
	}
	t := jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
	return f.jm.Submit(a.Kind(), t, dry, user, func(_ context.Context, _ jobs.Job, log jobs.Logger) (string, error) {
		log(false, "▶ lxc-apt")
		return "apt : 3 paquet(s)", nil
	})
}

func (f *fakeEngine) SetAnswers(key string, a map[string]string) error {
	if f.answers == nil {
		f.answers = map[string]map[string]string{}
	}
	f.answers[key] = a
	return nil
}

const nginxQ = "Update Nginx configuration? [Y/n]:"

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
	next := time.Date(2026, 11, 15, 3, 40, 0, 0, time.Local)
	srv, err := New(cfg, inv, Deps{Engine: eng, Jobs: jm, Detections: store, Batches: eng, NextDetection: func() time.Time { return next }}, log, "test")
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
	resp, body := h.do("GET", "/inventaire", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("inventaire : %d", resp.StatusCode)
	}
	for _, want := range []string{"termix", ">critique<", "tag « critique »", "il y a 5 min", "odin : délai dépassé", "&lt;script&gt;", "(nom indisponible)", "inconnu</span>", "pvestatd sur tyr", "Prochaine détection : 15/11 à 03:40"} {
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
	_, body := h.do("GET", "/inventaire?type=lxc", nil, nil)
	if !strings.Contains(body, "termix") || strings.Contains(body, ">PBS<") {
		t.Error("filtre par type inopérant")
	}
	_, body = h.do("GET", "/inventaire?q=203", nil, nil)
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
	if resp.StatusCode != http.StatusSeeOther || h.inv.triggered != 1 || resp.Header.Get("Location") != "/inventaire?type=lxc" {
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
		Apt: detect.Apt{Present: true, SecurityRepo: true, Total: 3, Security: 2, SecurityStrict: 1, StrictPackages: []string{"base-files"}, IndexAgeHours: 0,
			Packages: []detect.Package{{Name: "libssl3t64", Old: "3.5.7-1", New: "3.5.7-2", Security: true}, {Name: "base-files", Old: "13.8", New: "13.9"}}},
		Apps: []detect.App{{Name: "termix", Repo: "Termix-SSH/Termix", Installed: "release-2.6.1-tag", InstalledKnown: true, Latest: "v26.11.1",
			ChangelogURL: "https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"}},
	})
	_, body := h.do("GET", "/invites/loki/104", nil, nil)
	for _, want := range []string{"Debian GNU/Linux 13", "ancien format", "augmentation temporaire",
		"release-2.6.1-tag", "v26.11.1", `href="https://github.com/Termix-SSH/Termix/releases/tag/v26.11.1"`,
		`class="tv n`, "limite : 80 %", "il y a 10 min", `href="/invites/loki/104?onglet=paquets"`, "à renseigner"} {
		if !strings.Contains(body, want) {
			t.Errorf("page invité sans %q", want)
		}
	}
	_, pk := h.do("GET", "/invites/loki/104?onglet=paquets", nil, nil)
	for _, want := range []string{"1 correctif(s) de sécurité ne passent pas seuls", "libssl3t64", "base-files"} {
		if !strings.Contains(pk, want) {
			t.Errorf("onglet paquets sans %q", want)
		}
	}
	_, qs := h.do("GET", "/invites/loki/104?onglet=questions", nil, nil)
	if !strings.Contains(qs, "Update Nginx configuration?") {
		t.Error("onglet questions sans la question du script")
	}
	_, inv := h.do("GET", "/inventaire", nil, nil)
	for _, want := range []string{"2 sécu", "3 apt", "termix → v26.11.1", "Détecter tout (1)"} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventaire sans %q", want)
		}
	}
	if resp, _ := h.do("GET", "/invites/loki/9999", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("invité inconnu : %d", resp.StatusCode)
	}
}

func TestUpdateFlow(t *testing.T) {
	h := newHarness(t)
	h.login()
	_ = h.store.Put("loki/104", detect.Result{At: h.now, CS: detect.CS{Script: "termix", Prompts: []string{nginxQ}}, Apt: detect.Apt{Present: true}})

	_, page := h.do("GET", "/invites/loki/104", nil, nil)
	for _, want := range []string{"Tout mettre à jour", `href="/invites/loki/104/action/securite"`, `aria-disabled="true"`, "à renseigner"} {
		if !strings.Contains(page, want) {
			t.Errorf("page invité sans %q", want)
		}
	}
	if _, q := h.do("GET", "/invites/loki/104?onglet=questions", nil, nil); !strings.Contains(q, nginxQ) {
		t.Error("onglet questions sans la question")
	}
	tok := h.csrf()

	// Réponses : toutes obligatoires, puis enregistrées.
	resp, _ := h.do("POST", "/invites/loki/104/reponses", url.Values{"csrf": {tok}}, nil)
	if !strings.Contains(resp.Header.Get("Location"), "erreur=") {
		t.Errorf("réponse manquante acceptée : %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do("POST", "/invites/loki/104/reponses", url.Values{"csrf": {tok}, "r0": {"n"}}, nil)
	if !strings.Contains(resp.Header.Get("Location"), "info=") || h.eng.answers["loki/104"][nginxQ] != "n" {
		t.Errorf("réponses non enregistrées : %s %v", resp.Header.Get("Location"), h.eng.answers)
	}

	// Page de confirmation.
	_, conf := h.do("GET", "/invites/loki/104/action/complet", nil, nil)
	for _, want := range []string{"Ce qui sera fait", "apt-get --with-new-pkgs upgrade", "Simuler", "Appliquer", `name="confirme"`, "non</strong>"} {
		if !strings.Contains(conf, want) {
			t.Errorf("confirmation sans %q", want)
		}
	}
	if strings.Contains(conf, `name="nom"`) {
		t.Error("le nom n'est demandé que pour un invité critique")
	}
	if resp, _ := h.do("GET", "/invites/loki/104/action/nimportequoi", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("action inconnue : %d", resp.StatusCode)
	}

	// Appliquer sans cocher : refusé, aucune tâche.
	resp, _ = h.do("POST", "/invites/loki/104/action/complet", url.Values{"csrf": {tok}, "simulation": {"0"}}, nil)
	if !strings.Contains(resp.Header.Get("Location"), "/action/complet?erreur=") || len(h.jm.List("", 0)) != 0 {
		t.Errorf("application sans confirmation : %s", resp.Header.Get("Location"))
	}
	// Simulation : pas de confirmation nécessaire.
	resp, _ = h.do("POST", "/invites/loki/104/action/complet", url.Values{"csrf": {tok}, "simulation": {"1"}}, nil)
	id := strings.TrimPrefix(resp.Header.Get("Location"), "/taches/")
	if j := h.waitJob(id); !j.DryRun || j.Kind != jobs.KindFull {
		t.Errorf("simulation : %+v", j)
	}
	_, jp := h.do("GET", "/taches/"+id, nil, nil)
	if !strings.Contains(jp, "tout mettre à jour (simulation)") {
		t.Error("la page de tâche doit indiquer la simulation")
	}
	// Application confirmée.
	resp, _ = h.do("POST", "/invites/loki/104/action/complet", url.Values{"csrf": {tok}, "simulation": {"0"}, "confirme": {"1"}}, nil)
	id = strings.TrimPrefix(resp.Header.Get("Location"), "/taches/")
	if j := h.waitJob(id); j.DryRun || j.Status != jobs.Success {
		t.Errorf("application : %+v", j)
	}
	// Sans jeton CSRF : refusé.
	if resp, _ := h.do("POST", "/invites/loki/104/action/securite", url.Values{"simulation": {"1"}}, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("sans CSRF : %d", resp.StatusCode)
	}
}

func TestCriticalConfirmation(t *testing.T) {
	h := newHarness(t)
	h.inv.snap.Guests = append(h.inv.snap.Guests, inventory.Guest{Node: "tyr", Type: "lxc", VMID: 403, Name: "omv", Status: "running", Critical: true, CriticalReason: "nom contenant « omv »"})
	h.login()
	_, conf := h.do("GET", "/invites/tyr/403/action/securite", nil, nil)
	if !strings.Contains(conf, `name="nom"`) || !strings.Contains(conf, "invité critique") {
		t.Error("le nom doit être demandé pour un invité critique")
	}
	tok := h.csrf()
	resp, _ := h.do("POST", "/invites/tyr/403/action/securite", url.Values{"csrf": {tok}, "simulation": {"0"}, "confirme": {"1"}, "nom": {"autre"}}, nil)
	if !strings.Contains(resp.Header.Get("Location"), "erreur=") {
		t.Errorf("mauvais nom accepté : %s", resp.Header.Get("Location"))
	}
	resp, _ = h.do("POST", "/invites/tyr/403/action/securite", url.Values{"csrf": {tok}, "simulation": {"0"}, "confirme": {"1"}, "nom": {"omv"}}, nil)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/taches/") {
		t.Errorf("bon nom refusé : %s", resp.Header.Get("Location"))
	}
}

func TestTodoPage(t *testing.T) {
	h := newHarness(t)
	h.login()
	old := h.now.Add(-72 * time.Hour)
	_ = h.store.Put("loki/104", detect.Result{At: h.now.Add(-time.Hour), Apt: detect.Apt{Present: true, Total: 3, Security: 2, SecurityStrict: 1, StrictPackages: []string{"libssl3t64"}, Packages: []detect.Package{
		{Name: "libssl3t64", Old: "1", New: "2", Security: true, Since: old},
		{Name: "curl", Old: "1", New: "2", Security: true, Since: h.now.Add(-time.Hour)},
		{Name: "bash", Old: "1", New: "2"},
	}}, Apps: []detect.App{{Name: "termix", Installed: "1.0.0", InstalledKnown: true, Latest: "2.0.0", Since: old}}})
	_, body := h.do("GET", "/", nil, nil)
	for _, want := range []string{"À traiter", ">2</b>correctifs de sécurité", "termix", "depuis 3 j", ">libssl3t64<", ">curl<", "2 correctifs",
		`value="loki/104:securite"`, "Versions majeures", `value="loki/104:complet"`} {
		if !strings.Contains(body, want) {
			t.Errorf("« À traiter » sans %q", want)
		}
	}
	if strings.Contains(body, ">bash<") {
		t.Error("un paquet non lié à la sécurité ne doit pas apparaître dans le groupe Sécurité")
	}
	if resp, _ := h.do("GET", "/securite", nil, nil); resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/" {
		t.Errorf("ancienne page sécurité : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	if !strings.Contains(body, `action="/lot"`) || !strings.Contains(body, "Préparer le lot…") {
		t.Error("barre de sélection : préparation du lot attendue")
	}
}

func TestBatchFlow(t *testing.T) {
	h := newHarness(t)
	h.login()
	_ = h.store.Put("loki/104", detect.Result{At: h.now, Apt: detect.Apt{Present: true, Total: 3, Security: 2, SecurityStrict: 2}})
	// Préparation : sélection depuis « À traiter » (le doublon garde la première opération).
	_, page := h.do("GET", "/lot?sel=loki/104:securite&sel=loki/104:complet&sel=loki/203:securite&sel=loki/9999:securite&sel=n%27importe", nil, nil)
	for _, want := range []string{"Préparer un lot", `name="cle_0" value="loki/104"`, "3 paquets", `name="cle_1" value="loki/203"`, "ignoré : invité à confirmation renforcée", "Arrêter le lot au premier échec", "Appliquer le lot"} {
		if !strings.Contains(page, want) {
			t.Errorf("préparation sans %q", want)
		}
	}
	if strings.Contains(page, "cle_2") || !strings.Contains(page, `value="complet" selected`) {
		t.Error("invité inconnu gardé, ou « tout » n'a pas remplacé « sécurité » pour le même invité")
	}
	tok := h.csrf()
	form := url.Values{"csrf": {tok}, "cle_0": {"loki/104"}, "op_0": {"complet"}, "garder_0": {"1"}, "snap_0": {"1"}, "cle_1": {"loki/203"}, "op_1": {"securite"}, "arret": {"1"}, "mode": {"appliquer"}}
	resp, _ := h.do("POST", "/lot", form, nil)
	if !strings.Contains(resp.Header.Get("Location"), "erreur=") || h.eng.batch != nil {
		t.Errorf("lot appliqué sans confirmation : %s", resp.Header.Get("Location"))
	}
	form.Set("confirme", "1")
	resp, _ = h.do("POST", "/lot", form, nil)
	if resp.Header.Get("Location") != "/lots/lot-test" || len(h.eng.batch) != 1 || h.eng.batch[0].Op != engine.OpFull || !h.eng.batch[0].Snapshot || h.eng.batchDry || !h.eng.batchStop {
		t.Fatalf("lot : %s %+v dry=%v stop=%v", resp.Header.Get("Location"), h.eng.batch, h.eng.batchDry, h.eng.batchStop)
	}
	form.Set("mode", "simulation")
	form.Del("confirme")
	if resp, _ := h.do("POST", "/lot", form, nil); resp.Header.Get("Location") != "/lots/lot-test" || !h.eng.batchDry {
		t.Error("la simulation ne demande pas de confirmation")
	}
	_, lot := h.do("GET", "/lots/lot-test", nil, nil)
	if !strings.Contains(lot, "tout mettre à jour") || !strings.Contains(lot, "réussie") {
		t.Error("page du lot incomplète")
	}
	if _, tasks := h.do("GET", "/taches", nil, nil); !strings.Contains(tasks, "Lots récents") || !strings.Contains(tasks, `href="/lots/lot-test"`) {
		t.Error("lots absents de la page des tâches")
	}
	// Lot par tag, depuis l'inventaire groupé par tag.
	snap := h.inv.snap
	snap.Guests[0].Tags = append(snap.Guests[0].Tags, "media")
	h.inv.snap = snap
	_, inv := h.do("GET", "/inventaire?grouper=tag", nil, nil)
	if !strings.Contains(inv, `href="/lot?tag=media&amp;op=securite"`) || !strings.Contains(inv, "sans tag") {
		t.Error("groupes par tag ou lien de lot absents")
	}
	_, byTag := h.do("GET", "/lot?tag=media&op=securite", nil, nil)
	if !strings.Contains(byTag, `name="cle_0" value="loki/104"`) || !strings.Contains(byTag, "tag « media »") {
		t.Error("préparation d'un lot par tag")
	}
}

func TestRestartPages(t *testing.T) {
	h := newHarness(t)
	h.login()
	_ = h.store.Put("loki/104", detect.Result{At: h.now, Apt: detect.Apt{Present: true}, RestartUnits: []string{"nginx.service"}})
	_, body := h.do("GET", "/invites/loki/104", nil, nil)
	if !strings.Contains(body, "Redémarrer les services (1)…") || !strings.Contains(body, "/redemarrage?quoi=ct") {
		t.Error("carte Redémarrage absente de la fiche")
	}
	_, todo := h.do("GET", "/", nil, nil)
	if !strings.Contains(todo, `value="loki/104:services"`) || !strings.Contains(todo, "Redémarrages") {
		t.Error("redémarrage absent de « À traiter »")
	}
	_, inv := h.do("GET", "/inventaire", nil, nil)
	if !strings.Contains(inv, "1 service(s) à redémarrer") {
		t.Error("badge de services absent de l'inventaire")
	}
	_, conf := h.do("GET", "/invites/loki/104/redemarrage?quoi=services", nil, nil)
	if !strings.Contains(conf, "nginx.service") || !strings.Contains(conf, "systemctl restart") {
		t.Error("page de confirmation des services")
	}
	tok := h.csrf()
	resp, _ := h.do("POST", "/invites/loki/104/redemarrage?quoi=services", url.Values{"csrf": {tok}}, nil)
	if !strings.Contains(resp.Header.Get("Location"), "erreur=") || len(h.eng.restarted) != 0 {
		t.Error("redémarrage sans confirmation accepté")
	}
	resp, _ = h.do("POST", "/invites/loki/104/redemarrage?quoi=ct", url.Values{"csrf": {tok}, "confirme": {"1"}}, nil)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/taches/") || strings.Join(h.eng.restarted, ",") != "ct:loki/104" {
		t.Errorf("redémarrage du CT : %s %v", resp.Header.Get("Location"), h.eng.restarted)
	}
}

func TestShellPreviewSettings(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.Notify = []config.Notify{{Type: "ntfy", URL: "https://ntfy.sh/sujet-tres-secret?auth=jeton", Events: []string{"echec"}}}
	h.srv.cfg.Proxmox = []config.Endpoint{{Name: "loki", URL: "https://pve:8006", TokenID: "patchwarden@pve!inventaire", TokenSecret: "s3cret-du-jeton"}}
	snap := h.inv.snap
	snap.NodeStats = map[string]inventory.NodeStat{"loki": {Name: "loki", Online: true, CPU: .23, MemUsed: 61, MemTotal: 100,
		Storage: "omv-data", StorageType: "lvm", StorageUsed: 99, StorageTotal: 100,
		Storages: []inventory.StorageStat{{Name: "local-lvm", Type: "lvmthin", Used: 82, Total: 100}, {Name: "omv-data", Type: "lvm", Used: 99, Total: 100}}}}
	// Le stockage affiché est celui des disques des LXC, pas le disque de données d'une VM.
	_ = h.store.Put("loki/104", detect.Result{At: h.now, Snap: detect.SnapInfo{Known: true, Storages: []detect.StorageUse{{Name: "local-lvm", Type: "lvmthin", UsedPct: 82}}}})
	h.inv.snap = snap
	h.login()
	_, body := h.do("GET", "/inventaire", nil, nil)
	for _, want := range []string{"Stockage", "82 %", `class="fg w" width="82"`, "23 %"} {
		if !strings.Contains(body, want) {
			t.Errorf("menu des nœuds sans %q", want)
		}
	}
	if strings.Contains(body, "99 %") {
		t.Error("le stockage réservé à une VM ne doit pas être affiché")
	}
	for _, want := range []string{`class="acct"`, `data-theme-set="dark"`, "Se déconnecter"} {
		if !strings.Contains(body, want) {
			t.Errorf("panneau de gauche sans %q", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("style en ligne : interdit par la CSP")
	}
	resp, frag := h.do("GET", "/invites/loki/104/apercu", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(frag, "Ouvrir la fiche complète") || strings.Contains(frag, "<html") || strings.Contains(frag, "class=\"side\"") {
		t.Errorf("aperçu : %d", resp.StatusCode)
	}
	_, set := h.do("GET", "/reglages", nil, nil)
	if strings.Contains(set, "sujet-tres-secret") || strings.Contains(set, "jeton") && strings.Contains(set, "auth=") || strings.Contains(set, "s3cret-du-jeton") {
		t.Error("secret affiché dans les réglages")
	}
	if !strings.Contains(set, "https://ntfy.sh/…") || !strings.Contains(set, "défini (masqué)") {
		t.Error("réglages incomplets")
	}
}

func TestStepsFromLog(t *testing.T) {
	j := jobs.Job{Kind: jobs.KindFull, Status: jobs.Running, Target: jobs.Target{Node: "loki"}}
	var lines []jobs.Line
	for _, l := range []string{"  0. snapshot avant toute modification", "  2. apt-get --with-new-pkgs upgrade : 3 paquet(s)", "  3. update community-scripts (ct/termix.sh), sans terminal : termix",
		"▶ lxc-snapshot 104 pw-20261115-0141-complet 1 90 0 <description>", "pw.node_log=/var/log/patchwarden/104-x-snapshot.log", "snap.info=1", "▶ lxc-apt 104 full 0", "pw.apt_rc=0", "▶ lxc-cs-update 104 y 4 4096"} {
		lines = append(lines, jobs.Line{Text: l})
	}
	st := stepsFor(j, lines)
	if len(st) != 4 || st[0].State != "fait" || st[1].State != "fait" || st[2].State != "encours" || st[3].State != "" || st[0].Detail != "pw-20261115-0141-complet" {
		t.Fatalf("étapes : %+v", st)
	}
	j.Status = jobs.Failed
	if st := stepsFor(j, lines); st[2].State != "echec" {
		t.Errorf("échec non reporté : %+v", st[2])
	}
	if nodeLog(j, lines) != "loki:/var/log/patchwarden/104-x-snapshot.log" || takenSnapshot(j, lines) != "pw-20261115-0141-complet" {
		t.Error("journal du nœud ou snapshot pris")
	}
	if stepsFor(jobs.Job{Kind: jobs.KindDetect}, lines) != nil {
		t.Error("pas d'étapes pour une détection")
	}
}

func TestSnapshotUI(t *testing.T) {
	h := newHarness(t)
	h.login()
	csrf := h.csrf()

	// Page d'action : case à cocher, nom prévu ; envoyée avec la mise à jour.
	_ = h.eng.SetAnswers("loki/104", map[string]string{nginxQ: "y"})
	_, body := h.do("GET", "/invites/loki/104/action/complet", nil, nil)
	for _, want := range []string{`name="snapshot" value="1" >`, "pw-20261113-1805-complet", "Si le snapshot échoue, la mise à jour est annulée", `<input type="hidden" name="snapshot" value="1">`} {
		if !strings.Contains(body, want) {
			t.Errorf("page d'action sans %q", want)
		}
	}
	resp, _ := h.do("POST", "/invites/loki/104/action/complet", url.Values{"csrf": {csrf}, "simulation": {"0"}, "confirme": {"1"}, "snapshot": {"1"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || h.eng.lastSnap == nil || !*h.eng.lastSnap {
		t.Errorf("snapshot non transmis : %d %v", resp.StatusCode, h.eng.lastSnap)
	}
	resp, _ = h.do("POST", "/invites/loki/104/action/complet", url.Values{"csrf": {csrf}, "simulation": {"0"}, "confirme": {"1"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || *h.eng.lastSnap {
		t.Errorf("case décochée : snapshot transmis quand même")
	}

	// Page de l'invité : snapshots PatchWarden, réglage.
	det := detect.Result{At: h.now, Apt: detect.Apt{Present: true}, Snap: detect.SnapInfo{
		Known: true, Possible: true, Other: 2, Binds: 1,
		Storages: []detect.StorageUse{{Name: "local-lvm", Type: "lvmthin", UsedPct: 45}},
		PW:       []detect.Snapshot{{Name: "pw-20261115-0141-complet", Time: h.now, Description: "PatchWarden avant « tout mettre à jour »"}},
	}}
	if err := h.store.Put("loki/104", det); err != nil {
		t.Fatal(err)
	}
	_, body = h.do("GET", "/invites/loki/104?onglet=snapshots", nil, nil)
	for _, want := range []string{"pw-20261115-0141-complet", "/snapshots/pw-20261115-0141-complet/restaurer", "2 snapshot(s) manuel(s), jamais touchés", "local-lvm (lvmthin) : 45 %", "jamais cochée d'office"} {
		if !strings.Contains(body, want) {
			t.Errorf("page de l'invité sans %q", want)
		}
	}
	_, body = h.do("GET", "/inventaire", nil, nil)
	if !strings.Contains(body, "◉ snapshot") {
		t.Error("badge de snapshot absent de l'inventaire")
	}
	resp, _ = h.do("POST", "/invites/loki/104/snapshots/reglage", url.Values{"csrf": {csrf}, "reglage": {"toujours"}}, nil)
	if resp.StatusCode != http.StatusSeeOther || h.eng.prefs["loki/104"] != "toujours" {
		t.Errorf("réglage non enregistré : %v", h.eng.prefs)
	}

	// Retour arrière : page d'avertissement, nom à saisir.
	resp, body = h.do("GET", "/invites/loki/104/snapshots/pw-20261115-0141-complet/restaurer", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "sera perdu") || !strings.Contains(body, "de montage liés à l'hôte") {
		t.Errorf("page de retour arrière : %d", resp.StatusCode)
	}
	if resp, _ := h.do("GET", "/invites/loki/104/snapshots/avant-maj/restaurer", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("snapshot manuel : %d (404 attendu)", resp.StatusCode)
	}
	resp, _ = h.do("POST", "/invites/loki/104/snapshots/pw-20261115-0141-complet/restaurer", url.Values{"csrf": {csrf}, "nom": {"autre"}}, nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") || h.eng.rolled != "" {
		t.Errorf("mauvais nom accepté : %s", loc)
	}
	resp, _ = h.do("POST", "/invites/loki/104/snapshots/pw-20261115-0141-complet/restaurer", url.Values{"csrf": {csrf}, "nom": {"termix"}}, nil)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/taches/") || h.eng.rolled != "pw-20261115-0141-complet" {
		t.Errorf("retour arrière : %s", loc)
	}
	resp, _ = h.do("POST", "/invites/loki/104/snapshots/pw-20261115-0141-complet/supprimer", url.Values{"csrf": {csrf}}, nil)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "erreur=") {
		t.Errorf("suppression sans confirmation : %s", loc)
	}
}

func TestSnapshotImpossibleShown(t *testing.T) {
	h := newHarness(t)
	h.login()
	_, body := h.do("GET", "/invites/loki/203/action/securite", nil, nil)
	if !strings.Contains(body, "Impossible : le stockage de ce CT ne permet pas les snapshots") || strings.Contains(body, `name="snapshot" value="1"`) {
		t.Errorf("snapshot impossible mal affiché")
	}
}
