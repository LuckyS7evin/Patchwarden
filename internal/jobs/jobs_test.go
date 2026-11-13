package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var dev = Target{Node: "loki", VMID: 103, Type: "lxc", Name: "dev"}

func waitDone(t *testing.T, m *Manager, id string) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if j, _ := m.Get(id); j.Status.Finished() {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tâche %s non terminée", id)
	return Job{}
}

func TestSuccessLogAndPersistence(t *testing.T) {
	dir := t.TempDir()
	m, err := New(dir, 2, 100, quiet())
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.Submit(KindDetect, dev, false, "admin", func(_ context.Context, _ Job, log Logger) (string, error) {
		log(false, "ligne 1")
		log(true, "avertissement")
		return "75 paquets", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, m, j.ID)
	if done.Status != Success || done.Summary != "75 paquets" || done.StartedAt.IsZero() || done.EndedAt.IsZero() {
		t.Errorf("tâche : %+v", done)
	}
	m.Close()

	// Rechargement depuis le disque.
	m2, err := New(dir, 2, 100, quiet())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := m2.Get(j.ID)
	if !ok || got.Status != Success {
		t.Fatalf("tâche non rechargée : %+v", got)
	}
	lines, err := m2.Log(j.ID)
	if err != nil || len(lines) != 2 || lines[0].Text != "ligne 1" || !lines[1].Stderr {
		t.Errorf("journal relu : %v %+v", err, lines)
	}
}

func TestOneJobPerGuest(t *testing.T) {
	m, _ := New(t.TempDir(), 4, 100, quiet())
	defer m.Close()
	release := make(chan struct{})
	j1, err := m.Submit(KindDetect, dev, false, "admin", func(context.Context, Job, Logger) (string, error) {
		<-release
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Submit(KindDetect, dev, false, "admin", nil); !errors.Is(err, ErrBusy) {
		t.Errorf("seconde tâche sur le même invité acceptée : %v", err)
	}
	other := dev
	other.VMID = 104
	j3, err := m.Submit(KindDetect, other, false, "admin", func(context.Context, Job, Logger) (string, error) { return "", nil })
	if err != nil {
		t.Errorf("un autre invité doit pouvoir être traité : %v", err)
	}
	waitDone(t, m, j3.ID)
	if a, ok := m.ActiveFor(dev); !ok || a.ID != j1.ID {
		t.Errorf("tâche active : %+v %v", a, ok)
	}
	close(release)
	waitDone(t, m, j1.ID)
	if _, ok := m.ActiveFor(dev); ok {
		t.Error("verrou non libéré")
	}
	if _, err := m.Submit(KindDetect, dev, false, "admin", func(context.Context, Job, Logger) (string, error) { return "", nil }); err != nil {
		t.Errorf("nouvelle tâche après la fin refusée : %v", err)
	}
}

func TestMaxParallel(t *testing.T) {
	m, _ := New(t.TempDir(), 2, 100, quiet())
	defer m.Close()
	var running, peak int32
	release := make(chan struct{})
	var ids []string
	for i := 0; i < 5; i++ {
		tg := dev
		tg.VMID = 200 + i
		j, err := m.Submit(KindDetect, tg, false, "admin", func(context.Context, Job, Logger) (string, error) {
			n := atomic.AddInt32(&running, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			<-release
			atomic.AddInt32(&running, -1)
			return "", nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, j.ID)
	}
	time.Sleep(100 * time.Millisecond)
	queued := 0
	for _, id := range ids {
		if j, _ := m.Get(id); j.Status == Queued {
			queued++
		}
	}
	if queued != 3 {
		t.Errorf("3 tâches en attente attendues, obtenu %d", queued)
	}
	close(release)
	for _, id := range ids {
		waitDone(t, m, id)
	}
	if peak != 2 {
		t.Errorf("pic de tâches simultanées : %d", peak)
	}
}

func TestFailureAndPanic(t *testing.T) {
	m, _ := New(t.TempDir(), 2, 100, quiet())
	defer m.Close()
	j1, _ := m.Submit(KindDetect, dev, false, "admin", func(context.Context, Job, Logger) (string, error) {
		return "", errors.New("code 1")
	})
	if got := waitDone(t, m, j1.ID); got.Status != Failed || got.Error != "code 1" {
		t.Errorf("échec : %+v", got)
	}
	j2, _ := m.Submit(KindDetect, dev, false, "admin", func(context.Context, Job, Logger) (string, error) {
		panic("boum")
	})
	if got := waitDone(t, m, j2.ID); got.Status != Failed || got.Error == "" {
		t.Errorf("panique non capturée : %+v", got)
	}
}

func TestSubscribeLive(t *testing.T) {
	m, _ := New(t.TempDir(), 2, 100, quiet())
	defer m.Close()
	step := make(chan struct{})
	j, _ := m.Submit(KindDetect, dev, false, "admin", func(_ context.Context, _ Job, log Logger) (string, error) {
		log(false, "avant")
		<-step
		log(false, "pendant")
		return "fini", nil
	})
	time.Sleep(50 * time.Millisecond)
	past, ch, cancel, err := m.Subscribe(j.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if len(past) != 1 || past[0].Text != "avant" {
		t.Errorf("passé : %+v", past)
	}
	close(step)
	var got []string
	var done *Job
	for ev := range ch {
		if ev.Line != nil {
			got = append(got, ev.Line.Text)
		}
		if ev.Done != nil {
			done = ev.Done
		}
	}
	if len(got) != 1 || got[0] != "pendant" || done == nil || done.Summary != "fini" {
		t.Errorf("direct : %v %+v", got, done)
	}
	// Après la fin : tout vient du disque, sans canal.
	past, ch, _, _ = m.Subscribe(j.ID)
	if ch != nil || len(past) != 2 {
		t.Errorf("relecture : %v %+v", ch, past)
	}
}

func TestInterruptedOnRestart(t *testing.T) {
	dir := t.TempDir()
	// Simule une tâche restée « en cours » après un arrêt brutal.
	jdir := filepath.Join(dir, "jobs", "20261113-234002-abcdef")
	if err := os.MkdirAll(jdir, 0o750); err != nil {
		t.Fatal(err)
	}
	meta := `{"id":"20261113-234002-abcdef","kind":"détection","target":{"node":"loki","vmid":103},"status":"en cours"}`
	if err := os.WriteFile(filepath.Join(jdir, "meta.json"), []byte(meta), 0o640); err != nil {
		t.Fatal(err)
	}
	m, err := New(dir, 2, 100, quiet())
	if err != nil {
		t.Fatal(err)
	}
	j, ok := m.Get("20261113-234002-abcdef")
	if !ok || j.Status != Interrupted || j.Error == "" {
		t.Errorf("tâche non marquée interrompue : %+v", j)
	}
	if _, busy := m.ActiveFor(dev); busy {
		t.Error("une tâche interrompue ne doit pas bloquer l'invité")
	}
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	m, _ := New(dir, 4, 10, quiet())
	defer m.Close()
	base := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	var n int
	m.now = func() time.Time { n++; return base.Add(time.Duration(n) * time.Second) }
	for i := 0; i < 15; i++ {
		tg := dev
		tg.VMID = 300 + i
		j, _ := m.Submit(KindDetect, tg, false, "admin", func(context.Context, Job, Logger) (string, error) { return "", nil })
		waitDone(t, m, j.ID)
	}
	if got := len(m.List("", 0)); got != 10 {
		t.Errorf("rétention : %d tâches gardées", got)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "jobs"))
	if len(ents) != 10 {
		t.Errorf("répertoires restants : %d", len(ents))
	}
	if l := m.List("", 1); l[0].Target.VMID != 314 {
		t.Errorf("ordre : la plus récente doit être en tête : %+v", l[0])
	}
}
