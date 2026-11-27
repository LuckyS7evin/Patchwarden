package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

func fastVerify(t *testing.T) {
	t.Helper()
	r, a, w, p := verifyRetry, verifyAttempts, httpWait, httpPoll
	verifyRetry, verifyAttempts, httpWait, httpPoll = 10*time.Millisecond, 2, 300*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { verifyRetry, verifyAttempts, httpWait, httpPoll = r, a, w, p })
}

func TestProblems(t *testing.T) {
	before := &detect.Result{FailedUnits: []string{"vieux.service"}, DockerInfo: detect.Docker{List: []detect.Container{
		{Name: "web", State: "running"}, {Name: "db", State: "running", Health: "unhealthy"}, {Name: "arrete", State: "exited"},
	}}}
	after := detect.Result{FailedUnits: []string{"vieux.service", "nginx.service"}, DockerInfo: detect.Docker{List: []detect.Container{
		{Name: "web", State: "exited"}, {Name: "db", State: "running", Health: "unhealthy"},
	}}}
	list, transient := problems(before, after)
	if len(list) != 2 || !transient || !strings.Contains(strings.Join(list, ";"), "nginx.service") || !strings.Contains(strings.Join(list, ";"), "conteneur arrêté : web") {
		t.Errorf("problèmes : %v", list)
	}
	if l, _ := problems(before, *before); len(l) != 0 {
		t.Errorf("aucun changement : %v", l)
	}
}

func TestUpdateFailsWhenServiceBreaks(t *testing.T) {
	fastVerify(t)
	e := setup(t)
	e.detect(t)
	t.Setenv("FAKE_FAILED_UNIT", "nginx.service")
	j, err := e.eng.Execute(e.guest, ActSecurity, false, "admin", true, "", true)
	if err != nil {
		t.Fatal(err)
	}
	done := wait(t, e.eng.Jobs, j.ID)
	log := e.logOf(t, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "vérification") || !strings.Contains(done.Error, "service en échec : nginx.service") || !strings.Contains(done.Error, "retour arrière possible") {
		t.Fatalf("vérification : %+v\n%s", done, log)
	}
	if strings.Count(log, "▶ lxc-detect") < 2 {
		t.Errorf("pas de nouvel essai avant l'échec :\n%s", log)
	}
}

func TestUpdateHTTPCheck(t *testing.T) {
	fastVerify(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	e := setup(t)
	prefs, err := OpenPrefs(t.TempDir(), "verifications.json")
	if err != nil {
		t.Fatal(err)
	}
	e.eng.Checks = prefs
	if err := e.eng.SetCheckURL(e.guest.Key(), "pas une url"); err == nil {
		t.Error("adresse invalide acceptée")
	}
	if err := e.eng.SetCheckURL(e.guest.Key(), srv.URL); err != nil {
		t.Fatal(err)
	}
	e.detect(t)
	j, _ := e.eng.Execute(e.guest, ActSecurity, false, "admin", true, "", false)
	done := wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Success || !strings.Contains(done.Summary, "vérification réussie") || atomic.LoadInt32(&calls) < 3 {
		t.Fatalf("vérification HTTP : %+v (%d appels)\n%s", done, calls, e.logOf(t, j.ID))
	}

	// Service qui ne répond plus : échec après le délai.
	srv.Close()
	e.detect(t)
	j, _ = e.eng.Execute(e.guest, ActSecurity, false, "admin", true, "", false)
	done = wait(t, e.eng.Jobs, j.ID)
	if done.Status != jobs.Failed || !strings.Contains(done.Error, "ne répond pas correctement") {
		t.Errorf("service injoignable : %+v", done)
	}
}
