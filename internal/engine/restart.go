package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
)

// RestartPlan décrit les redémarrages utiles sur un invité.
type RestartPlan struct {
	Guest    inventory.Guest
	Det      *detect.Result
	Units    []string // services que « Redémarrer les services » relancera
	Excluded []string // services système : seul un redémarrage du CT les relance
	Procs    []string // processus hors service liés à d'anciennes bibliothèques
	Required bool     // fichier reboot-required présent
	Reboot   bool     // redémarrage du CT conseillé
	// Why : raison pour laquelle rien n'est possible (vide si possible).
	Why string
	// NeedName : invité critique, le nom doit être saisi pour le redémarrer.
	NeedName bool
}

// Needed : un redémarrage (services ou CT) est utile.
func (p RestartPlan) Needed() bool {
	return len(p.Units)+len(p.Excluded)+len(p.Procs) > 0 || p.Required
}

// CanServices / CanReboot : actions possibles.
func (p RestartPlan) CanServices() bool { return p.Why == "" && len(p.Units) > 0 }
func (p RestartPlan) CanReboot() bool   { return p.Why == "" }

// PlanRestart prépare les redémarrages d'un invité d'après sa dernière détection.
func (e *Engine) PlanRestart(g inventory.Guest) RestartPlan {
	p := RestartPlan{Guest: g, NeedName: g.Critical}
	if err := e.CanDetect(g); err != nil {
		p.Why = err.Error()
		return p
	}
	if e.IsSelf(g) {
		p.Why = "cet invité héberge PatchWarden : redémarrez-le à la main"
		return p
	}
	det, ok := e.Store.Get(target(g).Key())
	if !ok {
		p.Why = "aucune détection : lancez-la d'abord"
		return p
	}
	p.Det = &det
	if det.Special == "pve" {
		p.Why = "Proxmox VE est installé dans cet invité : PatchWarden ne le redémarre pas"
		return p
	}
	if det.Special != "" {
		p.NeedName = true
	}
	p.Units = det.RestartableUnits()
	for _, u := range det.RestartUnits {
		if !contains(p.Units, u) {
			p.Excluded = append(p.Excluded, u)
		}
	}
	p.Procs, p.Required, p.Reboot = det.RestartProcs, det.RebootRequired, det.RebootAdvised()
	return p
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// RestartServices redémarre, dans le CT, les services encore liés à des
// bibliothèques remplacées. La liste est établie par le wrapper dans le CT.
func (e *Engine) RestartServices(g inventory.Guest, user string, confirmed bool) (jobs.Job, error) {
	p := e.PlanRestart(g)
	if p.Why != "" {
		return jobs.Job{}, errors.New(p.Why)
	}
	if len(p.Units) == 0 {
		return jobs.Job{}, errors.New("aucun service à redémarrer d'après la dernière détection")
	}
	if !confirmed {
		return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
	}
	before := e.lastDetection(g)
	return e.Jobs.Submit(jobs.KindServices, target(g), false, user, func(ctx context.Context, job jobs.Job, log jobs.Logger) (string, error) {
		log(false, fmt.Sprintf("Services à redémarrer d'après la détection : %s", strings.Join(p.Units, ", ")))
		cmd := fmt.Sprintf("%s %d", verb(g, "restart-services"), g.VMID)
		log(false, "▶ "+cmd)
		out, errs, code, err := e.run(ctx, g.Node, cmd, log)
		if err != nil {
			return "", connLost(err, out)
		}
		n := 0
		for _, l := range out {
			if v, ok := strings.CutPrefix(l, "pw.restarted="); ok {
				fmt.Sscan(v, &n)
			}
		}
		summary := plural(n, "service redémarré", "services redémarrés")
		if err := explainCodes(code, errs, out, 50, 51); err != nil {
			return summary, err
		}
		return e.verify(ctx, g, before, job, log, summary)
	})
}

// Reboot redémarre le CT (pct reboot). typedName : nom saisi (invités critiques).
func (e *Engine) Reboot(g inventory.Guest, user string, confirmed bool, typedName string) (jobs.Job, error) {
	p := e.PlanRestart(g)
	if p.Why != "" {
		return jobs.Job{}, errors.New(p.Why)
	}
	if !confirmed {
		return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
	}
	if p.NeedName && strings.TrimSpace(typedName) != g.Name {
		return jobs.Job{}, fmt.Errorf("%w : saisissez exactement le nom de l'invité (%s)", ErrConfirm, g.Name)
	}
	before := e.lastDetection(g)
	return e.Jobs.Submit(jobs.KindReboot, target(g), false, user, func(ctx context.Context, job jobs.Job, log jobs.Logger) (string, error) {
		cmd := fmt.Sprintf("%s %d", verb(g, "reboot"), g.VMID)
		log(false, "▶ "+cmd)
		out, errs, code, err := e.run(ctx, g.Node, cmd, log)
		if err != nil {
			return "", connLost(err, out)
		}
		if err := explainCodes(code, errs, out, 52); err != nil {
			return "", err
		}
		if g.IsHost() {
			if err := e.waitHostBack(ctx, g, bootID(out), log); err != nil {
				return "", err
			}
		}
		return e.verify(ctx, g, before, job, log, guestNoun(g)+" redémarré")
	})
}

func bootID(out []string) string {
	id := ""
	for _, l := range out {
		if v, ok := strings.CutPrefix(l, "pw.boot_id="); ok {
			id = strings.TrimSpace(v)
		}
	}
	return id
}

// waitHostBack attend qu'un hôte autonome réponde de nouveau après son
// redémarrage, avec un identifiant de démarrage différent de before (le
// wrapper programme le redémarrage quelques secondes plus tard et rend la main).
func (e *Engine) waitHostBack(ctx context.Context, g inventory.Guest, before string, log jobs.Logger) error {
	back, poll := e.HostBack, e.HostPoll
	if back <= 0 {
		back = 10 * time.Minute
	}
	if poll <= 0 {
		poll = 15 * time.Second
	}
	log(false, fmt.Sprintf("Attente du retour de l'hôte (%s au plus)…", back))
	deadline := time.Now().Add(back)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
		var out []string
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		code, err := e.Runner.Run(cctx, g.Node, "ping", func(l sshx.Line) {
			if !l.Stderr {
				out = append(out, l.Text)
			}
		})
		cancel()
		if err == nil && code == 0 {
			if id := bootID(out); before == "" || (id != "" && id != before) {
				log(false, "Hôte de nouveau joignable, après un nouveau démarrage")
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("l'hôte n'a pas répondu après un nouveau démarrage dans les %s : vérifiez-le depuis la console de l'hébergeur", back)
		}
	}
}

// verify relance une détection après une action, vérifie l'invité et résume.
func (e *Engine) verify(ctx context.Context, g inventory.Guest, before *detect.Result, job jobs.Job, log jobs.Logger, summary string) (string, error) {
	res, err := e.afterOp(ctx, g, before, job, log)
	if err != nil {
		return summary, err
	}
	return summary + " · après : " + summarize(res) + " · vérification réussie", nil
}

// lastDetection renvoie la dernière détection d'un invité (nil si aucune).
func (e *Engine) lastDetection(g inventory.Guest) *detect.Result {
	if d, ok := e.Store.Get(target(g).Key()); ok {
		return &d
	}
	return nil
}

// explainCodes traduit les codes propres à un verbe (message PW-ERREUR du journal).
func explainCodes(code int, errs, out []string, known ...int) error {
	if code == 0 {
		return nil
	}
	for _, k := range known {
		if code == k {
			msg := strings.TrimPrefix(lastMatching(out, "PW-ERREUR: "), "PW-ERREUR: ")
			return fmt.Errorf("%s (code %d)", msg, code)
		}
	}
	return explainExit(code, errs)
}

func plural(n int, one, many string) string {
	if n > 1 {
		return fmt.Sprintf("%d %s", n, many)
	}
	return fmt.Sprintf("%d %s", n, one)
}
