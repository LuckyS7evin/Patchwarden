package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
)

var fakeWebp = []byte("RIFF\x10\x00\x00\x00WEBPVP8 fake")

func TestIconCandidates(t *testing.T) {
	cases := []struct {
		g    inventory.Guest
		det  *detect.Result
		want string
	}{
		{inventory.Guest{Name: "termix"}, &detect.Result{OSID: "debian", CS: detect.CS{Script: "termix"}}, "termix,debian"},
		{inventory.Guest{Name: "adguard"}, &detect.Result{OSID: "debian", CS: detect.CS{Script: "adguard"}}, "adguard-home,debian"},
		{inventory.Guest{Name: "OMV6"}, nil, "omv6,openmediavault"},
		{inventory.Guest{Name: "PBS"}, nil, "proxmox"},
		{inventory.Guest{Name: "dev"}, &detect.Result{OSID: "debian", CS: detect.CS{Script: "debian"}}, "dev,debian"},
		{inventory.Guest{Name: "teamspeak-server"}, nil, "teamspeak"},
	}
	for _, c := range cases {
		if got := strings.Join(iconCandidates(c.g, c.det), ","); got != c.want {
			t.Errorf("%s : %q, attendu %q", c.g.Name, got, c.want)
		}
	}
}

func TestIconStoreAndHandler(t *testing.T) {
	var hits int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.URL.Path {
		case "/termix.webp":
			_, _ = w.Write(fakeWebp)
		case "/piege.webp":
			_, _ = w.Write([]byte("<svg onload=alert(1)>")) // pas du WebP : refusé
		default:
			http.NotFound(w, r)
		}
	}))
	defer cdn.Close()
	st := newIconStore(t.TempDir(), cdn.URL, true)
	ctx := context.Background()
	if b, err := st.get(ctx, "termix"); err != nil || string(b) != string(fakeWebp) {
		t.Fatalf("téléchargement : %v", err)
	}
	if _, err := st.get(ctx, "termix"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.get(ctx, "inconnue"); err == nil {
		t.Error("icône absente acceptée")
	}
	_, _ = st.get(ctx, "inconnue")
	if _, err := st.get(ctx, "piege"); err == nil {
		t.Error("contenu non WebP accepté")
	}
	if _, err := st.get(ctx, "../etc/passwd"); err == nil {
		t.Error("nom dangereux accepté")
	}
	if hits != 3 {
		t.Errorf("cache : %d requêtes vers le CDN, 3 attendues (termix, inconnue, piege)", hits)
	}

	h := newHarness(t)
	h.srv.icons = st
	h.login()
	resp, body := h.do("GET", "/icones?n=absente&n=termix&l=termix", nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/webp" || body != string(fakeWebp) {
		t.Errorf("icône : %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	resp, body = h.do("GET", "/icones?n=absente&l=<b>x", nil, nil)
	if resp.Header.Get("Content-Type") != "image/svg+xml" || !strings.Contains(body, ">&lt;<") || strings.Contains(body, "<b>") {
		t.Errorf("repli sur l'initiale : %q", body)
	}
	_, inv := h.do("GET", "/", nil, nil)
	if !strings.Contains(inv, `src="/icones?l=termix&amp;n=termix"`) {
		t.Error("icône absente de l'inventaire")
	}
}
