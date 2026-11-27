package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/portainer"
	"github.com/LuckyS7evin/patchwarden/internal/registry"
)

// Faux docker (dans l'invité) : conteneurs décrits dans $FAKE_GUEST/docker/ctr
// (lignes docker.ctr déjà formatées), empreintes dans $FAKE_GUEST/docker/img.
// « compose pull » remplace l'empreinte de beszel par la nouvelle.
const fakeDocker = `#!/bin/bash
D="$FAKE_GUEST/docker"
[ -n "$FAKE_DOCKER" ] || exit 1
case "$1" in
info) exit 0 ;;
ps)
	if [[ "$*" == *label=com.docker.compose.project=* ]]; then
		a="$*"; p="${a##*label=com.docker.compose.project=}"; p="${p%% *}"
		awk -F'|' -v p="$p" '$6 == p { sub(/^docker.ctr=/, "", $1); print $1 }' "$D/ctr"
	else
		awk -F'|' '{ sub(/^docker.ctr=/, "", $1); print $1 }' "$D/ctr"
	fi ;;
inspect)
	f="$3"
	case "$f" in
	docker.ctr=*) cat "$D/ctr" ;;
	"{{.Image}}") cut -d'|' -f4 "$D/ctr" ;;
	"{{.Config.Image}}") cut -d'|' -f3 "$D/ctr" ;;
	*working_dir*) id="$4"; awk -F'|' -v id="$id" 'index($1, id) { print $8 }' "$D/ctr" ;;
	*config_files*) id="$4"; awk -F'|' -v id="$id" 'index($1, id) { print $9 }' "$D/ctr" ;;
	*) echo "" ;;
	esac ;;
image)
	# docker image inspect --format … <id ou référence> : empreintes, séparées par des virgules.
	a="${@: -1}"
	case "$a" in
	sha256:*) id="$a" ;;
	*) id="$(awk -F'|' -v r="$a" '$3 == r { print $4; exit }' "$D/ctr")" ;;
	esac
	awk -F'|' -v id="$id" '{ k = $1; sub(/^docker.img=/, "", k); if (k == id) printf "%s,", $2 }' "$D/img" ;;
compose)
	shift
	[ "$1" = version ] && { echo "2.29.1"; exit 0; }
	echo "docker compose $*" >> "$PCT_SET_LOG"
	case "$*" in
	*"config -q"*) exit 0 ;;
	*"config --images"*) echo "henrygd/beszel:latest" ;;
	*"--status running"*) echo "beszel" ;;
	*"--status exited"*) : ;;
	*" pull "*) echo "beszel Pulled"; sed -i 's#henrygd/beszel@sha256:old#henrygd/beszel@sha256:new#' "$D/img" ;;
	*" up "*) echo "Container beszel Recreated" ;;
	*) echo "beszel running" ;;
	esac ;;
esac
`

type fakePortainer struct {
	mu   sync.Mutex
	puts []map[string]any
}

func (f *fakePortainer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "jeton" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		stack := func(id int, name string) map[string]any {
			return map[string]any{"Id": id, "Name": name, "Type": 2, "Status": 1, "EndpointId": 2, "Env": []map[string]string{{"name": "TZ", "value": "Europe/Paris"}}}
		}
		switch {
		case r.URL.Path == "/api/endpoints":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": 1, "Name": "autre", "Status": 1}, {"Id": 2, "Name": "docker", "Type": 2, "Status": 1}})
		case r.URL.Path == "/api/endpoints/1/docker/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": "ffffffffffff0000"}})
		case r.URL.Path == "/api/endpoints/2/docker/containers/json":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": "bbbbbbbbbbbb1111"}, {"Id": "cccccccccccc2222"}})
		case r.URL.Path == "/api/stacks":
			_ = json.NewEncoder(w).Encode([]map[string]any{stack(12, "mealie"), stack(13, "dozzle")})
		case r.URL.Path == "/api/stacks/12" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(stack(12, "mealie"))
		case r.URL.Path == "/api/stacks/12/file":
			_, _ = w.Write([]byte(`{"StackFileContent":"services:\n  mealie:\n    image: ghcr.io/mealie-recipes/mealie:v1.8.0\n"}`))
		case r.URL.Path == "/api/stacks/12" && r.Method == http.MethodPut:
			if r.URL.Query().Get("endpointId") != "2" {
				http.Error(w, "endpoint", http.StatusBadRequest)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.puts = append(f.puts, body)
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Logf("Portainer : %s %s inattendu", r.Method, r.URL)
			http.NotFound(w, r)
		}
	})
}

func fakeRegistryHandler() http.Handler {
	digests := map[string]string{
		"/v2/henrygd/beszel/manifests/latest":         "sha256:new",
		"/v2/mealie-recipes/mealie/manifests/v1.8.0":  "sha256:m2",
		"/v2/amir20/dozzle/manifests/latest":          "sha256:d1",
		"/v2/portainer/portainer-ce/manifests/latest": "sha256:p2",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d, ok := digests[r.URL.Path]; ok {
			w.Header().Set("Docker-Content-Digest", d)
			return
		}
		if r.URL.Path == "/v2/mealie-recipes/mealie/tags/list" {
			_, _ = w.Write([]byte(`{"tags":["v1.7.0","v1.8.0","v1.9.0","v2.0.0-rc1","latest"]}`))
			return
		}
		http.NotFound(w, r)
	})
}

func setupDocker(t *testing.T) (*env, *fakePortainer) {
	t.Helper()
	e := setup(t)
	guest := filepath.Join(e.root, "guest")
	writeExec(t, filepath.Join(e.root, "bin", "docker"), fakeDocker)
	proj := filepath.Join(guest, "home", "beszel")
	_ = os.MkdirAll(filepath.Join(guest, "docker"), 0o755)
	_ = os.MkdirAll(proj, 0o755)
	_ = os.WriteFile(filepath.Join(proj, "docker-compose.yml"), []byte("services:\n  beszel:\n    image: henrygd/beszel\n"), 0o644)
	ctr := strings.Join([]string{
		"docker.ctr=aaaaaaaaaaaa0000|/beszel|henrygd/beszel:latest|sha256:i1|running|beszel|beszel|" + proj + "|" + filepath.Join(proj, "docker-compose.yml") + "||",
		"docker.ctr=bbbbbbbbbbbb1111|/mealie|ghcr.io/mealie-recipes/mealie:v1.8.0|sha256:i2|running|mealie|mealie|/data/compose/12|/data/compose/12/docker-compose.yml|v1.8.0|https://github.com/mealie-recipes/mealie",
		"docker.ctr=cccccccccccc2222|/dozzle|amir20/dozzle:latest|sha256:i3|running|dozzle|dozzle|/data/compose/13|/data/compose/13/docker-compose.yml||<no value>",
		"docker.ctr=dddddddddddd3333|/portainer|portainer/portainer-ce:latest|sha256:i4|running||||||",
	}, "\n") + "\n"
	img := "docker.img=sha256:i1|henrygd/beszel@sha256:old\ndocker.img=sha256:i2|ghcr.io/mealie-recipes/mealie@sha256:m1\ndocker.img=sha256:i3|amir20/dozzle@sha256:d1\ndocker.img=sha256:i4|portainer/portainer-ce@sha256:p1\n"
	_ = os.WriteFile(filepath.Join(guest, "docker", "ctr"), []byte(ctr), 0o644)
	_ = os.WriteFile(filepath.Join(guest, "docker", "img"), []byte(img), 0o644)
	t.Setenv("FAKE_DOCKER", "1")

	reg := httptest.NewTLSServer(fakeRegistryHandler())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "https://")
	rc := registry.New(time.Hour, reg.Client())
	rc.Hosts = map[string]string{"docker.io": host, "ghcr.io": host}
	e.eng.Registry = rc

	fp := &fakePortainer{}
	ps := httptest.NewServer(fp.handler(t))
	t.Cleanup(ps.Close)
	pc, err := portainer.New(config.Portainer{Name: "p1", URL: ps.URL, Token: "jeton"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e.eng.Portainers = map[string]Portainer{"p1": pc}
	e.eng.PortainerOrder = []string{"p1"}
	return e, fp
}

func TestDockerDetectAndUpdate(t *testing.T) {
	e, fp := setupDocker(t)
	done := e.detectGuest(t, e.guest)
	log := e.logOf(t, done.ID)
	if done.Status != jobs.Success {
		t.Fatalf("détection : %+v\n%s", done, log)
	}
	det, _ := e.eng.Store.Get(e.guest.Key())
	d := det.DockerInfo
	if len(d.List) != 4 || d.Compose != "2.29.1" || !d.Checked {
		t.Fatalf("conteneurs : %+v", d)
	}
	m, _ := d.Container("mealie")
	if m.Check != detect.CheckUpdate || m.NewTag != "v1.9.0" || m.ChangelogURL != "https://github.com/mealie-recipes/mealie/releases" || m.Since.IsZero() {
		t.Errorf("mealie : %+v", m)
	}
	if dz, _ := d.Container("dozzle"); dz.Check != detect.CheckOK || dz.Source != "" {
		t.Errorf("dozzle : %+v", dz)
	}
	groups := map[string]detect.DockerGroup{}
	for _, g := range d.Groups {
		groups[g.Key] = g
	}
	if g := groups["portainer-12"]; g.Instance != "p1" || g.EndpointID != 2 || g.Updates != 1 || g.Blocker != "" {
		t.Errorf("stack mealie : %+v", g)
	}
	if g := groups["portainer-13"]; g.Updates != 0 || g.Updatable() {
		t.Errorf("stack dozzle : %+v", g)
	}
	if g := groups["compose-beszel"]; g.Updates != 1 || g.Blocker != "" {
		t.Errorf("projet beszel : %+v", g)
	}
	if g := groups["run-portainer"]; !strings.Contains(g.Blocker, "Portainer lui-même") {
		t.Errorf("portainer : %+v", g)
	}
	if !strings.Contains(done.Summary, "3 images Docker à mettre à jour") {
		t.Errorf("résumé : %s", done.Summary)
	}

	p := e.eng.PlanDocker(e.guest, nil)
	if !p.OK() || len(p.Groups) != 2 || len(p.Newer) != 1 {
		t.Fatalf("plan : %+v", p)
	}
	if bad := e.eng.PlanDocker(e.guest, []string{"run-portainer"}); bad.OK() {
		t.Error("docker run accepté")
	}

	// Simulation : vérifications seulement.
	j, err := e.eng.ExecuteDocker(e.guest, nil, true, "admin", false, "", true)
	if err != nil {
		t.Fatal(err)
	}
	sim := wait(t, e.eng.Jobs, j.ID)
	simLog := e.logOf(t, sim.ID)
	if sim.Status != jobs.Success || len(fp.puts) != 0 || !strings.Contains(simLog, "lxc-docker-compose 104 beszel 1") || !strings.Contains(simLog, "simulation : re-déploiement non lancé") {
		t.Fatalf("simulation : %+v\n%s", sim, simLog)
	}

	if _, err := e.eng.ExecuteDocker(e.guest, nil, false, "admin", false, "", false); err == nil {
		t.Error("exécution sans confirmation acceptée")
	}
	j, err = e.eng.ExecuteDocker(e.guest, nil, false, "admin", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	real := wait(t, e.eng.Jobs, j.ID)
	realLog := e.logOf(t, real.ID)
	if real.Status != jobs.Success {
		t.Fatalf("mise à jour : %+v\n%s", real, realLog)
	}
	if len(fp.puts) != 1 || fp.puts[0]["pullImage"] != true || fp.puts[0]["prune"] != false || !strings.Contains(fp.puts[0]["stackFileContent"].(string), "mealie") {
		t.Errorf("re-déploiement Portainer : %+v", fp.puts)
	}
	if env, _ := fp.puts[0]["env"].([]any); len(env) != 1 {
		t.Errorf("variables de la stack non reprises : %+v", fp.puts[0]["env"])
	}
	set, _ := os.ReadFile(filepath.Join(e.root, "pctset.log"))
	for _, want := range []string{"-docker", "pull beszel", "up -d --no-deps beszel"} {
		if !strings.Contains(string(set), want) {
			t.Errorf("commandes sans %q :\n%s", want, set)
		}
	}
	det, _ = e.eng.Store.Get(e.guest.Key())
	if b, _ := det.DockerInfo.Container("beszel"); b.Check != detect.CheckOK {
		t.Errorf("beszel après mise à jour : %+v\n%s", b, realLog)
	}
	if !strings.Contains(real.Summary, "snapshot pw-") || !strings.Contains(real.Summary, "stack Portainer « mealie » : mise à jour") {
		t.Errorf("résumé : %s", real.Summary)
	}

	// Lot : l'opération Docker passe par le même plan.
	why := e.eng.PreviewBatch([]BatchRequest{{Guest: e.guest, Op: OpDocker}})
	if why[0] != "" {
		t.Errorf("lot Docker refusé : %s", why[0])
	}
}

func TestDockerWithoutPortainer(t *testing.T) {
	e, _ := setupDocker(t)
	e.eng.Portainers, e.eng.PortainerOrder = nil, nil
	e.detectGuest(t, e.guest)
	det, _ := e.eng.Store.Get(e.guest.Key())
	g, _ := det.DockerInfo.Group("portainer-12")
	if !strings.Contains(g.Blocker, "[[portainer]]") {
		t.Errorf("stack sans Portainer configuré : %+v", g)
	}
	p := e.eng.PlanDocker(e.guest, nil)
	if !p.OK() || len(p.Groups) != 1 || p.Groups[0].Key != "compose-beszel" {
		t.Errorf("plan : %+v", p)
	}
}
