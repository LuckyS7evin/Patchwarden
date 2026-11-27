package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/window"
)

// windowTick : intervalle de vérification des fenêtres (modifiable pour les tests).
var windowTick = 30 * time.Second

// Window renvoie une fenêtre de maintenance par son nom.
func (e *Engine) Window(name string) (window.Window, bool) {
	for _, w := range e.Windows {
		if w.Name == name {
			return w, true
		}
	}
	return window.Window{}, false
}

// WindowStatus : situation d'un invité vis-à-vis des fenêtres de maintenance.
type WindowStatus struct {
	Covered bool          // au moins une fenêtre concerne l'invité
	Open    bool          // l'une d'elles est ouverte maintenant
	Next    window.Window // prochaine fenêtre qui le concerne
	NextAt  time.Time
}

// WindowFor dit si un invité est dans une fenêtre de maintenance. Sans
// fenêtre qui le concerne, aucune restriction ne s'applique.
func (e *Engine) WindowFor(g inventory.Guest, now time.Time) WindowStatus {
	var st WindowStatus
	for _, w := range e.Windows {
		if !w.Applies(g.Tags) {
			continue
		}
		st.Covered = true
		if w.Open(now) {
			st.Open = true
		}
		if s, _ := w.Next(now); !s.IsZero() && (st.NextAt.IsZero() || s.Before(st.NextAt)) {
			st.Next, st.NextAt = w, s
		}
	}
	return st
}

func (e *Engine) guestByKey(key string) (inventory.Guest, bool) {
	if e.Guests == nil {
		return inventory.Guest{}, false
	}
	for _, g := range e.Guests() {
		if g.Key() == key {
			return g, true
		}
	}
	return inventory.Guest{}, false
}

// ScheduleBatch enregistre un lot confirmé, lancé à la prochaine ouverture
// de la fenêtre choisie (ou tout de suite si elle est ouverte).
func (e *Engine) ScheduleBatch(reqs []BatchRequest, stopOnFail bool, user, windowName string) (Batch, error) {
	w, ok := e.Window(windowName)
	if !ok {
		return Batch{}, fmt.Errorf("fenêtre de maintenance inconnue : %q", windowName)
	}
	b, _, err := e.newBatch(reqs, false, stopOnFail, user)
	if err != nil {
		return Batch{}, err
	}
	b.Status, b.Window = BatchScheduled, w.Name
	b.ScheduledAt, b.Until = w.Next(time.Now())
	e.storeBatch(b)
	e.Log.Info("lot programmé", "lot", b.ID, "fenêtre", w.Name, "à", b.ScheduledAt.Format("02/01 15:04"), "par", user)
	c, _ := e.Batches.Get(b.ID)
	return c, nil
}

// CancelBatch annule un lot programmé qui n'a pas commencé.
func (e *Engine) CancelBatch(id, user string) error {
	if e.Batches == nil {
		return errors.New("lots indisponibles")
	}
	done := false
	e.Batches.update(id, func(b *Batch) {
		if b.Status != BatchScheduled {
			return
		}
		b.Status, b.EndedAt, done = BatchCancelled, time.Now(), true
		for i := range b.Items {
			if b.Items[i].Status == ItemPending {
				b.Items[i].Status, b.Items[i].Error = ItemCancelled, "lot annulé par "+user
			}
		}
	})
	if !done {
		return errors.New("seul un lot programmé, pas encore commencé, peut être annulé")
	}
	return nil
}

// RunWindows lance les lots programmés à l'ouverture de leur fenêtre, et la
// sécurité automatique si elle est activée, jusqu'à l'annulation du contexte.
func (e *Engine) RunWindows(ctx context.Context) {
	t := time.NewTicker(windowTick)
	defer t.Stop()
	for {
		e.windowsTick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) windowsTick(ctx context.Context, now time.Time) {
	if e.Batches == nil {
		return
	}
	due := []Batch{}
	for _, b := range e.Batches.List(0) {
		if b.Scheduled() && !b.ScheduledAt.After(now) {
			due = append(due, b)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].ScheduledAt.Before(due[j].ScheduledAt) })
	for _, b := range due {
		if now.After(b.Until) {
			e.Batches.update(b.ID, func(bt *Batch) {
				bt.Status, bt.EndedAt = BatchCancelled, now
				for i := range bt.Items {
					if bt.Items[i].Status == ItemPending {
						bt.Items[i].Status, bt.Items[i].Error = ItemCancelled, "fenêtre de maintenance passée sans exécution (PatchWarden arrêté ?)"
					}
				}
			})
			continue
		}
		e.Batches.update(b.ID, func(bt *Batch) { bt.Status = BatchRunning })
		go e.runScheduled(ctx, b.ID)
	}
	e.autoSecurityTick(ctx, now)
}

// runScheduled détecte d'abord les invités du lot (plan revérifié sur une
// détection du jour), puis l'exécute.
func (e *Engine) runScheduled(ctx context.Context, id string) {
	b, ok := e.Batches.Get(id)
	if !ok {
		return
	}
	e.detectFirst(ctx, b, "fenêtre « "+b.Window+" »")
	e.runBatch(id, nil)
}

// detectFirst lance une détection pour chaque invité du lot et attend la fin.
func (e *Engine) detectFirst(ctx context.Context, b Batch, by string) {
	seen := map[string]bool{}
	var ids []string
	for _, it := range b.Items {
		if it.Status != ItemPending || seen[it.Key()] {
			continue
		}
		seen[it.Key()] = true
		g, ok := e.guestByKey(it.Key())
		if !ok {
			continue
		}
		if j, err := e.Detect(g, by); err == nil {
			ids = append(ids, j.ID)
		}
	}
	for _, id := range ids {
		if j := e.waitJob(ctx, id); j.Status != jobs.Success {
			e.Log.Warn("détection avant un lot programmé", "tâche", id, "statut", j.Status, "erreur", j.Error)
		}
	}
}

// outsideWindow : avertissement quand l'invité a une fenêtre de maintenance
// et qu'elle n'est pas ouverte (l'action reste possible).
func (e *Engine) outsideWindow(g inventory.Guest) string {
	st := e.WindowFor(g, time.Now())
	if !st.Covered || st.Open {
		return ""
	}
	return "hors fenêtre de maintenance : prochaine « " + st.Next.Name + " » le " + window.FormatTime(st.NextAt) + " (programmez un lot pour cette fenêtre, ou continuez maintenant)"
}

// MaintenanceWindows renvoie les fenêtres configurées.
func (e *Engine) MaintenanceWindows() []window.Window { return e.Windows }
