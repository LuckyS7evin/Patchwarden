package engine

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/config"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/notify"
)

type inbox struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (b *inbox) get() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]map[string]any(nil), b.msgs...)
}

func withInbox(t *testing.T, e *env, events []string) *inbox {
	t.Helper()
	b := &inbox{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		b.mu.Lock()
		b.msgs = append(b.msgs, m)
		b.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	e.eng.Notify = notify.New([]config.Notify{{Type: "webhook", URL: srv.URL, Events: events}}, srv.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.eng.PublicURL = "http://pw.lan:8094"
	return b
}

func waitMsgs(b *inbox, n int) []map[string]any {
	for i := 0; i < 200 && len(b.get()) < n; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return b.get()
}

func TestScheduledDetectionReport(t *testing.T) {
	e := setup(t)
	box := withInbox(t, e, []string{"securite", "applis", "echec"})
	ghost := e.guest
	ghost.VMID, ghost.Name = 999, "fantome"
	stopped := e.guest
	stopped.VMID, stopped.Status = 108, "stopped"
	guests := []inventory.Guest{e.guest, ghost, stopped}

	r := e.eng.ScheduledDetection(context.Background(), guests)
	if r.Started != 2 || r.Skipped != 1 || len(r.Failures) != 1 || r.NewSecCount != 1 || len(r.NewApps) != 2 {
		t.Fatalf("rapport : %+v", r)
	}
	msgs := waitMsgs(box, 3)
	if len(msgs) != 3 {
		t.Fatalf("3 notifications attendues (sécurité, applis, échec), %d : %v", len(msgs), msgs)
	}
	var all []string
	for _, m := range msgs {
		all = append(all, m["event"].(string)+"|"+m["title"].(string)+"|"+m["message"].(string)+"|"+m["url"].(string))
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{
		"securite|PatchWarden : 1 nouveau(x) correctif(s) de sécurité|termix (loki/104) : 1 nouveau(x), 1 en attente|http://pw.lan:8094/securite",
		"termix (loki/104) : termix release-2.6.1-tag → v26.11.1",
		"echec|PatchWarden : détection planifiée, 1 échec(s)|fantome (loki/999)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("notifications sans %q :\n%s", want, joined)
		}
	}

	// Seconde exécution : rien de nouveau, seul l'échec est signalé.
	r2 := e.eng.ScheduledDetection(context.Background(), guests)
	if r2.NewSecCount != 0 || len(r2.NewApps) != 0 {
		t.Errorf("rien de nouveau attendu : %+v", r2)
	}
	if msgs := waitMsgs(box, 4); len(msgs) != 4 || msgs[3]["event"] != "echec" {
		t.Errorf("seconde exécution : %v", msgs)
	}
}

func TestNotifyJob(t *testing.T) {
	e := setup(t)
	box := withInbox(t, e, []string{"succes", "echec"})
	e.eng.Jobs.OnFinish = e.eng.NotifyJob
	e.detect(t) // détection : pas de notification
	_ = e.eng.Answers.Set(e.guest.Key(), map[string]string{nginxPrompt: "y"})
	j, _ := e.eng.Execute(e.guest, ActSecurity, true, "admin", false, "") // simulation : pas de notification
	wait(t, e.eng.Jobs, j.ID)
	j, err := e.eng.Execute(e.guest, ActSecurity, false, "admin", true, "")
	if err != nil {
		t.Fatal(err)
	}
	wait(t, e.eng.Jobs, j.ID)
	msgs := waitMsgs(box, 1)
	if len(msgs) != 1 || msgs[0]["event"] != "succes" || !strings.Contains(msgs[0]["title"].(string), "sécurité uniquement réussi sur termix") ||
		msgs[0]["url"] != "http://pw.lan:8094/taches/"+j.ID {
		t.Errorf("notification de fin : %v", msgs)
	}
}
