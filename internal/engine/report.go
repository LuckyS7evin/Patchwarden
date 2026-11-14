package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/notify"
)

// link renvoie l'URL publique d'une page, ou "".
func (e *Engine) link(path string) string {
	if e.PublicURL == "" {
		return ""
	}
	return strings.TrimRight(e.PublicURL, "/") + path
}

// NotifyJob signale la fin d'une mise à jour réelle (pas les simulations ni
// les détections, dont les nouveautés passent par le rapport planifié).
func (e *Engine) NotifyJob(j jobs.Job) {
	if e.Notify == nil || j.Kind == jobs.KindDetect || j.DryRun {
		return
	}
	name := fmt.Sprintf("%s (%s/%d)", j.Target.Name, j.Target.Node, j.Target.VMID)
	m := notify.Message{URL: e.link("/taches/" + j.ID)}
	switch j.Status {
	case jobs.Success:
		m.Event, m.Priority = notify.EvSuccess, 2
		m.Title = fmt.Sprintf("PatchWarden : %s réussi sur %s", j.Kind, j.Target.Name)
		m.Body = name + "\n" + j.Summary
	default:
		m.Event, m.Priority = notify.EvFailure, 4
		m.Title = fmt.Sprintf("PatchWarden : %s %s sur %s", j.Kind, j.Status, j.Target.Name)
		m.Body = name + "\n" + j.Error
	}
	e.Notify.Notify(m)
}

// Report résume une détection planifiée.
type Report struct {
	Start, End  time.Time
	Started     int
	Skipped     int
	Failures    []string
	NewSecurity []string // « termix (loki/104) : 3 nouveau(x), 65 en attente »
	NewApps     []string // « termix (loki/104) : release-2.6.1-tag → v26.11.1 »
	NewSecCount int
}

// ScheduledDetection détecte tous les invités éligibles, attend la fin des
// tâches, puis envoie un rapport des nouveautés (rien s'il n'y en a pas).
func (e *Engine) ScheduledDetection(ctx context.Context, guests []inventory.Guest) Report {
	r := Report{Start: time.Now()}
	var started []jobs.Job
	for _, g := range guests {
		j, err := e.Detect(g, "planificateur")
		if err != nil {
			r.Skipped++
			continue
		}
		started = append(started, j)
	}
	r.Started = len(started)
	e.Log.Info("détection planifiée lancée", "tâches", r.Started, "ignorés", r.Skipped)

	byKey := map[string]inventory.Guest{}
	for _, g := range guests {
		byKey[g.Key()] = g
	}
	for _, j := range started {
		done := e.waitJob(ctx, j.ID)
		label := fmt.Sprintf("%s (%s)", j.Target.Name, j.Target.Key())
		if done.Status != jobs.Success {
			r.Failures = append(r.Failures, label+" : "+firstNonEmpty(done.Error, string(done.Status)))
			continue
		}
		det, ok := e.Store.Get(j.Target.Key())
		if !ok {
			continue
		}
		sec, apps := det.NewSince(r.Start)
		if len(sec) > 0 {
			r.NewSecCount += len(sec)
			r.NewSecurity = append(r.NewSecurity, fmt.Sprintf("%s : %d nouveau(x), %d en attente", label, len(sec), det.Apt.Security))
		}
		for _, a := range apps {
			r.NewApps = append(r.NewApps, fmt.Sprintf("%s : %s %s → %s", label, a.Name, a.Installed, a.Latest))
		}
	}
	r.End = time.Now()
	sort.Strings(r.NewSecurity)
	sort.Strings(r.NewApps)
	e.Log.Info("détection planifiée terminée", "nouveaux_correctifs", r.NewSecCount, "nouvelles_versions", len(r.NewApps), "échecs", len(r.Failures))
	e.sendReport(r)
	return r
}

func (e *Engine) sendReport(r Report) {
	if e.Notify == nil {
		return
	}
	if len(r.NewSecurity) > 0 {
		e.Notify.Notify(notify.Message{
			Event: notify.EvSecurity, Priority: 4, URL: e.link("/securite"),
			Title: fmt.Sprintf("PatchWarden : %d nouveau(x) correctif(s) de sécurité", r.NewSecCount),
			Body:  strings.Join(r.NewSecurity, "\n"),
		})
	}
	if len(r.NewApps) > 0 {
		e.Notify.Notify(notify.Message{
			Event: notify.EvApps, Priority: 3, URL: e.link("/"),
			Title: fmt.Sprintf("PatchWarden : %d nouvelle(s) version(s) d'application", len(r.NewApps)),
			Body:  strings.Join(r.NewApps, "\n"),
		})
	}
	if len(r.Failures) > 0 {
		e.Notify.Notify(notify.Message{
			Event: notify.EvFailure, Priority: 4, URL: e.link("/taches"),
			Title: fmt.Sprintf("PatchWarden : détection planifiée, %d échec(s)", len(r.Failures)),
			Body:  strings.Join(r.Failures, "\n"),
		})
	}
}

func (e *Engine) waitJob(ctx context.Context, id string) jobs.Job {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if j, ok := e.Jobs.Get(id); !ok || j.Status.Finished() {
			return j
		}
		select {
		case <-ctx.Done():
			j, _ := e.Jobs.Get(id)
			return j
		case <-t.C:
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
