package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

func TestCycleStoppedGuest(t *testing.T) {
	e := setup(t)
	e.detect(t)
	stopped := filepath.Join(e.root, "guest", "stopped")
	_ = os.WriteFile(stopped, nil, 0o644)
	g := e.guest
	g.Status = "stopped"

	running := e.guest
	if err := e.eng.CanCycle(running); err == nil {
		t.Error("cycle accepté sur un invité démarré")
	}
	if _, err := e.eng.Cycle(g, ActSecurity, false, "admin", false, "", false); err == nil {
		t.Error("cycle sans confirmation accepté")
	}
	j, err := e.eng.Cycle(g, ActSecurity, false, "admin", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Success || done.Kind != jobs.KindCycle || !strings.Contains(done.Summary, "CT arrêté de nouveau") || !strings.Contains(done.Summary, "vérification réussie") {
		t.Fatalf("cycle : %+v\n%s", done, log)
	}
	sets := e.pctSets()
	for _, want := range []string{"pct start 104", "pct snapshot 104", "pct shutdown 104 --timeout 180"} {
		if !strings.Contains(sets, want) {
			t.Errorf("commandes sans %q :\n%s", want, sets)
		}
	}
	if _, err := os.Stat(stopped); err != nil {
		t.Error("l'invité n'est pas arrêté à la fin")
	}

	// Échec de la vérification (service injoignable) : l'invité est quand même arrêté.
	fastVerify(t)
	prefs, _ := OpenPrefs(t.TempDir(), "verifications.json")
	e.eng.Checks = prefs
	_ = e.eng.SetCheckURL(g.Key(), "http://127.0.0.1:9")
	j, _ = e.eng.Cycle(g, ActSecurity, false, "admin", true, "", false)
	done = wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "vérification") || strings.Count(e.pctSets(), "pct shutdown") != 2 {
		t.Errorf("échec : %+v\n%s", done, e.pctSets())
	}
}

func TestDockerPrune(t *testing.T) {
	e, _ := setupDocker(t)
	e.detectGuest(t, e.guest)
	if det, _ := e.eng.Store.Get(e.guest.Key()); det.DockerInfo.Dangling != 2 {
		t.Fatalf("images sans nom détectées : %d", det.DockerInfo.Dangling)
	}
	j, err := e.eng.DockerPrune(e.guest, true, "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	sim := wait(t, e.eng.Jobs, j.ID)
	if sim.Status != jobs.Success || strings.Contains(e.pctSets(), "docker image prune") || !strings.Contains(sim.Summary, "images sans nom (anciennes versions) : 2") {
		t.Fatalf("simulation : %+v", sim)
	}
	if _, err := e.eng.DockerPrune(e.guest, false, "admin", false); err == nil {
		t.Error("nettoyage sans confirmation accepté")
	}
	j, _ = e.eng.DockerPrune(e.guest, false, "admin", true)
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Success || !strings.Contains(done.Summary, "2 images sans nom supprimées") || !strings.Contains(done.Summary, "240MB") {
		t.Fatalf("nettoyage : %+v\n%s", done, e.logOf(t, j.ID))
	}
	if det, _ := e.eng.Store.Get(e.guest.Key()); det.DockerInfo.Dangling != 0 {
		t.Error("compteur non remis à zéro")
	}
}
