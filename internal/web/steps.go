package web

import (
	"regexp"
	"strings"

	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

// stepView est une étape d'une tâche. Son état se déduit du journal : une
// ligne contenant l'un des marqueurs Start la démarre, une ligne contenant
// l'un des marqueurs Done la termine. Les mêmes règles sont appliquées en
// direct par tache.js (attributs data-debut / data-fin, séparés par « | »).
type stepView struct {
	Label, Detail string
	Start, Done   string
	State         string // "", "encours", "fait", "echec"
}

var snapLineRe = regexp.MustCompile(`▶ lxc-snapshot \d+ (pw-[0-9]{8}-[0-9]{4}-[a-z]+)`)

func planLine(lines []jobs.Line, contains string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l.Text)
		if len(t) > 3 && t[0] >= '0' && t[0] <= '9' && strings.Contains(t, contains) {
			if _, after, ok := strings.Cut(t, ". "); ok {
				return after
			}
			return t
		}
	}
	return ""
}

func anyLine(lines []jobs.Line, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l.Text, sub) {
			return true
		}
	}
	return false
}

// stepsFor décrit les étapes d'une tâche de mise à jour ou de retour arrière
// (aucune pour une détection ou une suppression de snapshot).
func stepsFor(j jobs.Job, lines []jobs.Line) []stepView {
	var steps []stepView
	switch j.Kind {
	case jobs.KindSecurity, jobs.KindFull:
		if anyLine(lines, "0. snapshot avant") {
			d := "avant toute modification ; annule tout s'il échoue"
			for _, l := range lines {
				if m := snapLineRe.FindStringSubmatch(l.Text); m != nil {
					d = m[1]
				}
			}
			if j.DryRun {
				d = "vérification seulement"
			}
			steps = append(steps, stepView{Label: "Snapshot", Detail: d, Start: "▶ lxc-snapshot", Done: "snap.info=1| possible"})
		}
		apt := planLine(lines, "apt-get --with-new-pkgs upgrade")
		if j.DryRun {
			apt = "simulation (apt-get -s) · " + apt
		}
		steps = append(steps, stepView{Label: "Paquets apt", Detail: apt, Start: "▶ lxc-apt", Done: "pw.apt_rc="})
		if cs := planLine(lines, "update community-scripts"); cs != "" {
			steps = append(steps, stepView{Label: "Application", Detail: cs, Start: "▶ lxc-cs-update|▶ update community-scripts", Done: "pw.update_rc=|serait lancé"})
		}
		if !j.DryRun {
			steps = append(steps, stepView{Label: "Vérification", Detail: "détection après la mise à jour", Start: "▶ lxc-detect", Done: "pw.end=1"})
		}
	case jobs.KindRollback:
		steps = append(steps,
			stepView{Label: "Retour au snapshot", Detail: "CT arrêté puis restauré (pct rollback)", Start: "▶ lxc-rollback", Done: "terminé"},
			stepView{Label: "Redémarrage", Detail: "s'il tournait avant", Start: "PW: redémarrage du CT|PW: état après", Done: "PW: état après"},
			stepView{Label: "Vérification", Detail: "détection après le retour arrière", Start: "▶ lxc-detect", Done: "pw.end=1"},
		)
	default:
		return nil
	}
	for _, l := range lines {
		advance(steps, l.Text)
	}
	if j.Status.Finished() {
		for i := range steps {
			if steps[i].State == "encours" {
				if j.Status == jobs.Success {
					steps[i].State = "fait"
				} else {
					steps[i].State = "echec"
				}
			}
		}
	}
	return steps
}

func hasAny(text, markers string) bool {
	for _, m := range strings.Split(markers, "|") {
		if m != "" && strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// advance applique une ligne du journal aux étapes.
func advance(steps []stepView, text string) {
	for i := range steps {
		s := &steps[i]
		if s.State == "encours" && hasAny(text, s.Done) {
			s.State = "fait"
			return
		}
		if s.State == "" && hasAny(text, s.Start) {
			for k := 0; k < i; k++ {
				if steps[k].State == "encours" {
					steps[k].State = "fait"
				}
			}
			s.State = "encours"
			if hasAny(text, s.Done) {
				s.State = "fait"
			}
			return
		}
	}
}

// lineClass colore une ligne du journal.
func lineClass(l jobs.Line) string {
	t := strings.TrimSpace(l.Text)
	switch {
	case l.Stderr || strings.HasPrefix(t, "PW-ERREUR") || strings.HasPrefix(t, "PW-ALERTE") || strings.HasPrefix(t, "⚠"):
		return "err"
	case strings.HasPrefix(t, "▶") || strings.HasPrefix(t, "PW:"):
		return "pw"
	case strings.Contains(t, "[OK]") || strings.HasPrefix(t, "✔"):
		return "okl"
	}
	return ""
}

// nodeLog : journal complet de l'opération sur le nœud (« nœud:/chemin »).
func nodeLog(j jobs.Job, lines []jobs.Line) string {
	for _, l := range lines {
		if p, ok := strings.CutPrefix(strings.TrimSpace(l.Text), "pw.node_log="); ok {
			return j.Target.Node + ":" + p
		}
	}
	return ""
}

// takenSnapshot : snapshot pris pendant une mise à jour réelle.
func takenSnapshot(j jobs.Job, lines []jobs.Line) string {
	if j.DryRun {
		return ""
	}
	for _, l := range lines {
		if m := snapLineRe.FindStringSubmatch(l.Text); m != nil {
			return m[1]
		}
	}
	return ""
}
