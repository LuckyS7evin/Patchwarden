package schedule

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestNextAfter(t *testing.T) {
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("fuseau Europe/Paris absent")
	}
	times := []clock{{3, 40}, {14, 0}}
	at := func(s string) time.Time {
		v, _ := time.ParseInLocation("2006-01-02 15:04", s, paris)
		return v
	}
	for now, want := range map[string]string{
		"2026-11-14 01:00": "2026-11-14 03:40",
		"2026-11-14 03:40": "2026-11-14 14:00", // strictement après
		"2026-11-14 15:00": "2026-11-15 03:40",
		"2026-10-24 22:00": "2026-10-25 03:40", // nuit du passage à l'heure d'hiver
	} {
		if got := nextAfter(times, at(now)); !got.Equal(at(want)) {
			t.Errorf("après %s : %s, attendu %s", now, got.Format("2006-01-02 15:04 MST"), want)
		}
	}
}

func TestRunTriggers(t *testing.T) {
	ran := make(chan struct{}, 1)
	d := New([]string{"00:00"}, func(context.Context) { ran <- struct{}{} }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !d.Enabled() || d.Next().IsZero() {
		t.Fatal("planificateur inactif")
	}
	// Horloge simulée : l'échéance tombe 50 ms après « maintenant ».
	base := time.Now()
	d.now = func() time.Time {
		n := time.Now()
		midnight := time.Date(n.Year(), n.Month(), n.Day()+1, 0, 0, 0, 0, n.Location())
		return midnight.Add(-50 * time.Millisecond).Add(n.Sub(base))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("la tâche n'a pas été lancée")
	}
	if New(nil, nil, nil).Enabled() {
		t.Error("sans heure, le planificateur doit être inactif")
	}
}
