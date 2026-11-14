// Package schedule déclenche des tâches à des heures fixes, chaque jour.
package schedule

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Daily lance run aux heures locales données (« HH:MM »), tous les jours.
type Daily struct {
	times []clock
	run   func(context.Context)
	log   *slog.Logger
	now   func() time.Time

	mu   sync.Mutex
	next time.Time
}

type clock struct{ h, m int }

// New prépare un planificateur ; les heures ont été validées par la configuration.
func New(at []string, run func(context.Context), log *slog.Logger) *Daily {
	d := &Daily{run: run, log: log, now: time.Now}
	for _, s := range at {
		t, err := time.Parse("15:04", s)
		if err != nil {
			continue
		}
		d.times = append(d.times, clock{t.Hour(), t.Minute()})
	}
	sort.Slice(d.times, func(i, j int) bool {
		return d.times[i].h*60+d.times[i].m < d.times[j].h*60+d.times[j].m
	})
	return d
}

// Enabled indique si au moins une heure est programmée.
func (d *Daily) Enabled() bool { return d != nil && len(d.times) > 0 }

// Next renvoie la prochaine exécution prévue (zéro si rien n'est programmé).
func (d *Daily) Next() time.Time {
	if !d.Enabled() {
		return time.Time{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.next.IsZero() {
		return nextAfter(d.times, d.now())
	}
	return d.next
}

// nextAfter calcule la prochaine occurrence strictement postérieure à now, en
// heure locale (les changements d'heure sont gérés par time.Date).
func nextAfter(times []clock, now time.Time) time.Time {
	var best time.Time
	for day := 0; day <= 1; day++ {
		for _, c := range times {
			t := time.Date(now.Year(), now.Month(), now.Day()+day, c.h, c.m, 0, 0, now.Location())
			if t.After(now) && (best.IsZero() || t.Before(best)) {
				best = t
			}
		}
		if !best.IsZero() {
			return best
		}
	}
	return best
}

// Run attend chaque échéance et lance la tâche, jusqu'à l'annulation du contexte.
// Une exécution encore en cours à l'échéance suivante n'est pas doublée.
func (d *Daily) Run(ctx context.Context) {
	if !d.Enabled() {
		return
	}
	for {
		next := nextAfter(d.times, d.now())
		d.mu.Lock()
		d.next = next
		d.mu.Unlock()
		d.log.Info("prochaine détection planifiée", "à", next.Format("02/01 15:04"))
		timer := time.NewTimer(next.Sub(d.now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		d.run(ctx)
	}
}
