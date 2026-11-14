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

// Cas de TYR : le cluster ne connaît plus l'état des invités du nœud
// (« unknown », sans nom) ; la liste est relue sur le nœud lui-même.
func TestUnknownNodeStatusIsCompleted(t *testing.T) {
	srv, fp := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[
			 {"id":"lxc/104","type":"lxc","vmid":104,"node":"loki","name":"termix","status":"running"},
			 {"id":"lxc/114","type":"lxc","vmid":114,"node":"tyr","status":"unknown","tags":"community-script;media"},
			 {"id":"qemu/403","type":"qemu","vmid":403,"node":"tyr","status":"unknown","tags":"critique"},
			 {"id":"lxc/116","type":"lxc","vmid":116,"node":"tyr","status":"unknown"}]}`))
		case "/api2/json/nodes/tyr/lxc":
			_, _ = w.Write([]byte(`{"data":[{"vmid":"114","name":"jellyfin","status":"running","tags":"community-script;media"},{"vmid":"116","name":"ai-chat","status":"stopped"}]}`))
		case "/api2/json/nodes/tyr/qemu":
			_, _ = w.Write([]byte(`{"data":[{"vmid":403,"name":"OMV6","status":"running","template":0}]}`))
		default:
			t.Errorf("requête inattendue : %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	c, _ := New(endpoint(srv.URL, fp), 5*time.Second)
	g, err := c.Guests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[int]Resource{}
	for _, r := range g {
		by[r.VMID] = r
	}
	if by[114].Name != "jellyfin" || by[114].Status != "running" || by[114].Tags != "community-script;media" {
		t.Errorf("114 : %+v", by[114])
	}
	if by[403].Name != "OMV6" || by[403].Status != "running" || by[403].Tags != "critique" {
		t.Errorf("403 : %+v", by[403])
	}
	if by[116].Status != "stopped" || by[104].Name != "termix" {
		t.Errorf("116/104 : %+v %+v", by[116], by[104])
	}
}

func TestUnknownNodeStatusNodeDown(t *testing.T) {
	srv, fp := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/cluster/resources" {
			_, _ = w.Write([]byte(`{"data":[{"id":"lxc/114","type":"lxc","vmid":114,"node":"tyr","status":"unknown"}]}`))
			return
		}
		http.Error(w, "nœud injoignable", http.StatusInternalServerError)
	})
	c, _ := New(endpoint(srv.URL, fp), 5*time.Second)
	g, err := c.Guests(context.Background())
	if err != nil || len(g) != 1 || g[0].Status != "unknown" {
		t.Errorf("les données partielles doivent être gardées : %v %+v", err, g)
	}
}
