package engine

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

const (
	exitStartFail    = 53
	exitAlreadyUp    = 54
	exitShutdownFail = 55
)

// CanCycle dit si un invité arrêté peut être démarré, mis à jour puis arrêté.
func (e *Engine) CanCycle(g inventory.Guest) error {
	switch {
	case e.Runner == nil:
		return ErrNoSSH
	case g.Template:
		return ErrTemplate
	case g.Type != "lxc" && g.Type != "qemu":
		return ErrNotLXC
	case g.Status != "stopped":
		return errors.New("invité démarré : utilisez les mises à jour habituelles")
	case g.Stale:
		return ErrStaleNode
	case e.HasNode != nil && !e.HasNode(g.Node):
		return fmt.Errorf("%w (%s)", ErrNodeNoSSH, g.Node)
	}
	if d, ok := e.Store.Get(target(g).Key()); ok && d.Special == "pve" {
		return errors.New("Proxmox VE est installé dans cet invité : PatchWarden n'y agit pas")
	}
	return nil
}

// CycleNeedName : confirmation renforcée (invité critique, ou OMV/PBS d'après
// la dernière détection connue).
func (e *Engine) CycleNeedName(g inventory.Guest) bool {
	if g.Critical {
		return true
	}
	d, ok := e.Store.Get(target(g).Key())
	return ok && d.Special != ""
}

// Cycle démarre un invité arrêté, le détecte, applique l'action (ou sa
// simulation), le vérifie, puis l'arrête proprement, même en cas d'échec. Le
// plan est établi après le démarrage, sur une détection du jour.
func (e *Engine) Cycle(g inventory.Guest, a Action, dryRun bool, user string, confirmed bool, typedName string, snapshot bool) (jobs.Job, error) {
	if err := e.CanCycle(g); err != nil {
		return jobs.Job{}, err
	}
	if a != ActSecurity && a != ActFull {
		return jobs.Job{}, fmt.Errorf("action inconnue : %q", a)
	}
	if !dryRun && !confirmed {
		return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
	}
	if !dryRun && e.CycleNeedName(g) && strings.TrimSpace(typedName) != g.Name {
		return jobs.Job{}, fmt.Errorf("%w : saisissez exactement le nom de l'invité (%s)", ErrConfirm, g.Name)
	}
	return e.Jobs.Submit(jobs.KindCycle, target(g), dryRun, user, func(ctx context.Context, job jobs.Job, log jobs.Logger) (summary string, err error) {
		noun := guestNoun(g)
		log(false, fmt.Sprintf("%s %d (%s) arrêté : démarrage, détection, « %s »%s, puis arrêt propre (même en cas d'échec)", noun, g.VMID, g.Name, a.Label(), map[bool]string{true: " en simulation", false: ""}[dryRun]))
		cmd := verb(g, "start") + " " + strconv.Itoa(g.VMID)
		log(false, "▶ "+cmd)
		out, errs, code, rerr := e.run(ctx, g.Node, cmd, log)
		if rerr != nil {
			return "", connLost(rerr, out)
		}
		switch code {
		case 0:
		case exitAlreadyUp:
			return "", errors.New("l'invité a été démarré entre-temps : rien n'est fait (et il n'est pas arrêté)")
		case exitStartFail:
			return "", errors.New(strings.TrimPrefix(lastMatching(out, "PW-ERREUR: "), "PW-ERREUR: "))
		default:
			return "", explainExit(code, errs)
		}
		defer func() {
			log(false, "")
			cmd := verb(g, "shutdown") + " " + strconv.Itoa(g.VMID)
			log(false, "▶ "+cmd)
			out, errs, code, serr := e.run(context.WithoutCancel(ctx), g.Node, cmd, log)
			if serr == nil {
				serr = explainCodes(code, errs, out, exitShutdownFail)
			}
			if serr != nil {
				log(true, "⚠ arrêt impossible : "+serr.Error())
				if err == nil {
					err = fmt.Errorf("opération faite, mais arrêt impossible : %w ; l'invité reste démarré", serr)
				} else {
					err = fmt.Errorf("%w · arrêt impossible : %v ; l'invité reste démarré", err, serr)
				}
				return
			}
			summary = strings.TrimPrefix(summary+" · "+noun+" arrêté de nouveau", " · ")
		}()

		run := g
		run.Status = "running"
		if _, err := e.detectRun(ctx, run, job.ID, log); err != nil {
			return "", fmt.Errorf("détection après le démarrage : %w", err)
		}
		p := e.PlanFor(run, a)
		if !p.OK() {
			return "", errors.New(p.Blockers[0])
		}
		if !dryRun && p.NeedName && strings.TrimSpace(typedName) != g.Name {
			return "", fmt.Errorf("%w : %s demande la saisie de son nom (relancez depuis sa fiche)", ErrConfirm, g.Name)
		}
		if snapshot && !p.Snap.Possible {
			return "", errors.New("snapshot impossible : " + p.Snap.Why)
		}
		log(false, "")
		return e.updateFunc(p, dryRun, snapshot, user)(ctx, job, log)
	})
}

// DockerPrune supprime (ou liste, en simulation) les images Docker sans nom
// d'un invité : anciennes versions laissées par les mises à jour.
func (e *Engine) DockerPrune(g inventory.Guest, dryRun bool, user string, confirmed bool) (jobs.Job, error) {
	if err := e.CanDetect(g); err != nil {
		return jobs.Job{}, err
	}
	det, ok := e.Store.Get(target(g).Key())
	if !ok || !det.Docker {
		return jobs.Job{}, errors.New("aucun Docker détecté dans cet invité")
	}
	if !dryRun && !confirmed {
		return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
	}
	return e.Jobs.Submit(jobs.KindPrune, target(g), dryRun, user, func(ctx context.Context, job jobs.Job, log jobs.Logger) (string, error) {
		dry := "0"
		if dryRun {
			dry = "1"
		}
		cmd := verb(g, "docker-prune") + " " + strconv.Itoa(g.VMID) + " " + dry
		log(false, "▶ "+cmd)
		out, errs, code, err := e.run(ctx, g.Node, cmd, log)
		if err != nil {
			return "", connLost(err, out)
		}
		if err := explainCompose(code, errs, out); err != nil {
			return "", err
		}
		n := 0
		for _, l := range out {
			if v, ok := strings.CutPrefix(l, "pw.pruned="); ok {
				n, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		if dryRun {
			return strings.TrimPrefix(lastMatching(out, "PW: images sans nom"), "PW: "), nil
		}
		if d, ok := e.Store.Get(target(g).Key()); ok {
			d.DockerInfo.Dangling = 0
			_ = e.Store.Put(target(g).Key(), d)
		}
		s := plural(n, "image sans nom supprimée", "images sans nom supprimées")
		if l := lastMatching(out, "Total reclaimed space"); l != "voir le journal" {
			s += " · " + strings.TrimSpace(l)
		}
		return s, nil
	})
}
