package proxmox

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
)

const sample = `{"data":[
 {"id":"lxc/103","type":"lxc","vmid":103,"node":"loki","name":"dev","status":"running","tags":"community-script;os","template":0},
 {"id":"qemu/203","type":"qemu","vmid":203,"node":"loki","name":"PBS","status":"running","tags":"critique","template":0}
]}`

func server(t *testing.T, h http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv, formatFingerprint(sum[:])
}

func endpoint(url, fp string) config.Endpoint {
	return config.Endpoint{Name: "test", URL: url, TokenID: "patchwarden@pve!inventaire", TokenSecret: "s3cret", Fingerprint: fp}
}

func TestGuestsWithPinnedFingerprint(t *testing.T) {
	srv, fp := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/cluster/resources" || r.URL.Query().Get("type") != "vm" {
			t.Errorf("requête inattendue : %s", r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "PVEAPIToken=patchwarden@pve!inventaire=s3cret" {
			t.Errorf("en-tête d'authentification : %q", got)
		}
		_, _ = w.Write([]byte(sample))
	})
	c, err := New(endpoint(srv.URL, fp), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.Guests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 2 || g[0].VMID != 103 || g[0].Type != "lxc" || g[1].Tags != "critique" {
		t.Errorf("résultat inattendu : %+v", g)
	}
}

func TestWrongFingerprintIsRejected(t *testing.T) {
	srv, _ := server(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sample)) })
	wrong := strings.Repeat("00:", 31) + "00"
	c, err := New(endpoint(srv.URL, wrong), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Guests(context.Background()); err == nil || !strings.Contains(err.Error(), "empreinte du certificat inattendue") {
		t.Fatalf("empreinte erronée acceptée : %v", err)
	}
}

func TestHTTPErrorsAreExplained(t *testing.T) {
	for code, want := range map[int]string{401: "jeton refusé", 403: "PVEAuditor", 500: "HTTP 500"} {
		srv, fp := server(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", code) })
		c, _ := New(endpoint(srv.URL, fp), 5*time.Second)
		_, err := c.Guests(context.Background())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("HTTP %d : erreur %v, attendu %q", code, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("le secret apparaît dans l'erreur : %v", err)
		}
	}
}
