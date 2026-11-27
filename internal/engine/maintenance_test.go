package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/window"
)

// openWindow : fenêtre ouverte depuis 10 minutes, pour encore 2 heures.
func openWindow(t *testing.T, name string, tags ...string) window.Window {
	t.Helper()
	w, err := window.New(name, nil, time.Now().Add(-10*time.Minute).Format("15:04"), 130*time.Minute, tags)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func waitBatchDone(t *testing.T, e *Engine, id string) Batch {
	t.Helper()
	for i := 0; i < 1500; i++ {
		if b, _ := e.Batches.Get(id); b.Status != BatchRunning && b.Status != BatchScheduled {
			return b
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, _ := e.Batches.Get(id)
	t.Fatalf("lot non terminé : %+v", b)
	return b
}

func TestScheduledBatchRunsInWindow(t *testing.T) {
	e := setup(t)
	e.detect(t)
	g := e.guest
	e.eng.Guests = func() []inventory.Guest { return []inventory.Guest{g} }
	closed, _ := window.New("dimanche", []string{"dim"}, "03:00", time.Hour, nil)
	e.eng.Windows = []window.Window{openWindow(t, "test"), closed}

	if _, err := e.eng.ScheduleBatch([]BatchRequest{{Guest: g, Op: OpSecurity}}, true, "admin", "absente"); err == nil {
		t.Error("fenêtre inconnue acceptée")
	}
	// Lot programmé dans une fenêtre fermée : annulable, pas lancé.
	later, err := e.eng.ScheduleBatch([]BatchRequest{{Guest: g, Op: OpSecurity}}, true, "admin", "dimanche")
	if err != nil || later.Status != BatchScheduled || later.ScheduledAt.Weekday() != time.Sunday {
		t.Fatalf("lot programmé : %+v %v", later, err)
	}
	if err := e.eng.CancelBatch(later.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if b, _ := e.eng.Batches.Get(later.ID); b.Status != BatchCancelled || b.Items[0].Status != ItemCancelled {
		t.Errorf("annulation : %+v", b)
	}

	// Fenêtre ouverte : lancé au passage suivant, après une détection.
	b, err := e.eng.ScheduleBatch([]BatchRequest{{Guest: g, Op: OpSecurity}}, true, "admin", "test")
	if err != nil {
		t.Fatal(err)
	}
	e.eng.windowsTick(context.Background(), time.Now())
	done := waitBatchDone(t, e.eng, b.ID)
	if done.Status != BatchDone || done.Items[0].Status != ItemSuccess {
		t.Fatalf("lot dans la fenêtre : %+v", done)
	}
	if n := len(e.eng.Jobs.List(g.Key(), 0)); n < 3 { // détection préalable + détection de la fenêtre + mise à jour
		t.Errorf("détection avant le lot attendue : %d tâche(s)", n)
	}

	// Fenêtre passée pendant un arrêt de PatchWarden : lot annulé, jamais lancé.
	missed, _ := e.eng.ScheduleBatch([]BatchRequest{{Guest: g, Op: OpSecurity}}, true, "admin", "test")
	e.eng.windowsTick(context.Background(), time.Now().Add(3*time.Hour))
	if m, _ := e.eng.Batches.Get(missed.ID); m.Status != BatchCancelled || !strings.Contains(m.Items[0].Error, "passée") {
		t.Errorf("fenêtre manquée : %+v", m)
	}
}

func TestOutsideWindowWarning(t *testing.T) {
	e := setup(t)
	e.detect(t)
	closed, _ := window.New("dimanche", []string{"dim"}, "03:00", time.Hour, nil)
	e.eng.Windows = []window.Window{closed}
	if time.Now().Weekday() == time.Sunday && closed.Open(time.Now()) {
		t.Skip("fenêtre ouverte au moment du test")
	}
	p := e.eng.PlanFor(e.guest, ActSecurity)
	if !strings.Contains(strings.Join(p.Warnings, ";"), "hors fenêtre de maintenance") {
		t.Errorf("avertissement absent : %v", p.Warnings)
	}
	other, _ := window.New("media", nil, "03:00", time.Hour, []string{"media"})
	e.eng.Windows = []window.Window{other}
	if p := e.eng.PlanFor(e.guest, ActSecurity); strings.Contains(strings.Join(p.Warnings, ";"), "hors fenêtre") {
		t.Error("avertissement pour un invité qu'aucune fenêtre ne concerne")
	}
}

func TestAutoSecurity(t *testing.T) {
	e := setup(t)
	g := e.guest
	g.Tags = []string{"auto-securite"}
	e.eng.Guests = func() []inventory.Guest { return []inventory.Guest{g} }
	e.eng.Windows = []window.Window{openWindow(t, "nuit")}
	state, err := OpenPrefs(t.TempDir(), "auto.json")
	if err != nil {
		t.Fatal(err)
	}
	// Désactivée : rien ne se passe.
	e.eng.windowsTick(context.Background(), time.Now())
	time.Sleep(100 * time.Millisecond)
	if len(e.eng.Batches.List(0)) != 0 || len(e.eng.Jobs.List("", 0)) != 0 {
		t.Fatal("sécurité automatique lancée alors qu'elle est désactivée")
	}
	e.eng.Auto = AutoConfig{Enabled: true, Tag: "auto-securite", Window: "nuit", State: state}
	if n := e.eng.NextAuto(time.Now()); n.IsZero() {
		t.Error("prochaine exécution inconnue")
	}
	e.eng.windowsTick(context.Background(), time.Now())
	var b Batch
	for i := 0; i < 1500 && b.ID == ""; i++ {
		if l := e.eng.Batches.List(0); len(l) > 0 {
			b = l[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	if b.ID == "" {
		t.Fatal("aucun lot de sécurité automatique")
	}
	done := waitBatchDone(t, e.eng, b.ID)
	if !done.Auto || done.By != AutoUser || done.Status != BatchDone || done.Items[0].Op != OpSecurity || done.Items[0].Status != ItemSuccess {
		t.Fatalf("lot automatique : %+v", done)
	}
	// Une seule exécution par ouverture de fenêtre, même après un redémarrage.
	e.eng.windowsTick(context.Background(), time.Now())
	time.Sleep(100 * time.Millisecond)
	if n := len(e.eng.Batches.List(0)); n != 1 {
		t.Errorf("%d lots : la sécurité automatique a tourné deux fois", n)
	}
	if !e.eng.NextAuto(time.Now()).After(time.Now().Add(time.Hour)) {
		t.Error("prochaine exécution : la fenêtre en cours est déjà traitée")
	}
}
