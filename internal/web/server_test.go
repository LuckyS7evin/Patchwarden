package web

import (
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
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"golang.org/x/crypto/bcrypt"
)

type fakeInv struct {
	snap      inventory.Snapshot
	triggered int
}

func (f *fakeInv) Current() (inventory.Snapshot, bool) { return f.snap, false }
func (f *fakeInv) TriggerRefresh()                     { f.triggered++ }

type harness struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	c   *http.Client
	inv *fakeInv
	now time.Time
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
		},
	}}
	srv, err := New(cfg, inv, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: srv, inv: inv, now: time.Date(2026, 11, 13, 18, 5, 0, 0, time.UTC)}
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
	for _, want := range []string{"termix", "community-scripts", "confirmation renforcée", "tag « critique »", "il y a 5 min", "odin : délai dépassé", "&lt;script&gt;"} {
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
