package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
)

// AutoConfig reprend la section [auto_security]. Désactivée par défaut.
type AutoConfig struct {
	Enabled  bool
	Tag      string // invités concernés
	Window   string // fenêtre [[maintenance]]
	Snapshot bool   // snapshot avant chaque mise à jour (invité ignoré s'il est impossible)
	// State : dernière fenêtre traitée (pas de double passage après un redémarrage).
	State *PrefStore
}

// AutoUser : auteur des tâches de la sécurité automatique.
const AutoUser = "sécurité automatique"

// AutoCandidates renvoie les invités concernés par la sécurité automatique
// (tag, LXC ou VM) ; les exclusions (critiques, OMV, PBS, invité de
// PatchWarden, arrêtés) sont appliquées au moment du lot, avec leur raison.
func (e *Engine) AutoCandidates() []inventory.Guest {
	if !e.Auto.Enabled || e.Guests == nil {
		return nil
	}
	var out []inventory.Guest
	for _, g := range e.Guests() {
		if (g.Type == "lxc" || g.Type == "qemu") && !g.Template && hasTagFold(g.Tags, e.Auto.Tag) {
			out = append(out, g)
		}
	}
	return out
}

// NextAuto renvoie la prochaine exécution de la sécurité automatique (zéro si désactivée).
func (e *Engine) NextAuto(now time.Time) time.Time {
	if !e.Auto.Enabled {
		return time.Time{}
	}
	w, ok := e.Window(e.Auto.Window)
	if !ok {
		return time.Time{}
	}
	s, _ := w.Next(now)
	if !s.After(now) && e.autoDone(s) {
		s, _ = w.Next(s.Add(w.Duration + time.Minute))
	}
	return s
}

func hasTagFold(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func (e *Engine) autoDone(start time.Time) bool {
	return e.Auto.State != nil && e.Auto.State.Get("derniere_fenetre") == start.Format(time.RFC3339)
}

// autoSecurityTick lance la sécurité automatique une fois par ouverture de
// sa fenêtre.
func (e *Engine) autoSecurityTick(ctx context.Context, now time.Time) {
	if !e.Auto.Enabled {
		return
	}
	w, ok := e.Window(e.Auto.Window)
	if !ok || !w.Open(now) {
		return
	}
	start, end := w.Next(now)
	if e.autoDone(start) {
		return
	}
	if e.Auto.State != nil {
		if err := e.Auto.State.Set("derniere_fenetre", start.Format(time.RFC3339)); err != nil {
			e.Log.Error("sécurité automatique : état non enregistré", "erreur", err)
			return
		}
	}
	go e.runAuto(ctx, w.Name, start, end)
}

// runAuto : détection des invités concernés, puis « Sécurité uniquement »
// en lot (arrêt au premier échec), avec snapshot et vérification.
func (e *Engine) runAuto(ctx context.Context, windowName string, start, end time.Time) {
	guests := e.AutoCandidates()
	e.Log.Info("sécurité automatique : début", "fenêtre", windowName, "invités", len(guests))
	if len(guests) == 0 {
		return
	}
	probe := Batch{}
	for _, g := range guests {
		probe.Items = append(probe.Items, BatchItem{Node: g.Node, VMID: g.VMID, Name: g.Name, Status: ItemPending})
	}
	e.detectFirst(ctx, probe, AutoUser)
	var reqs []BatchRequest
	for _, g := range guests {
		if det, ok := e.Store.Get(target(g).Key()); ok && det.Apt.SecurityStrict > 0 {
			reqs = append(reqs, BatchRequest{Guest: g, Op: OpSecurity, Snapshot: e.Auto.Snapshot})
		}
	}
	if len(reqs) == 0 {
		e.Log.Info("sécurité automatique : aucun correctif à appliquer", "fenêtre", windowName)
		return
	}
	b, gm, err := e.newBatch(reqs, false, true, AutoUser)
	if err != nil {
		if errors.Is(err, ErrEmptyBatch) {
			e.Log.Info("sécurité automatique : aucun invité éligible (critiques, OMV, PBS, snapshot impossible…)", "fenêtre", windowName)
		} else {
			e.Log.Error("sécurité automatique", "erreur", err)
		}
		return
	}
	b.Auto, b.Window, b.ScheduledAt, b.Until = true, windowName, start, end
	e.storeBatch(b)
	e.runBatch(b.ID, gm)
}
