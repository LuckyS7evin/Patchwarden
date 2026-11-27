package web

import (
	"fmt"
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

var snapLineRe = regexp.MustCompile(`▶ (?:lxc|vm)-snapshot \d+ (pw-[0-9]{8}-[0-9]{4}-[a-z]+)`)

var (
	stackStepRe   = regexp.MustCompile(`^\d+\. (stack Portainer « [^»]+ ») : .*\(stack n° (\d+)\)`)
	composeStepRe = regexp.MustCompile(`^\d+\. (projet compose « ([^»]+) »)`)
)

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
			steps = append(steps, stepView{Label: "Vérification", Detail: "détection, services et conteneurs comparés à l'état d'avant", Start: "▶ lxc-detect"})
		}
	case jobs.KindDocker:
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
		for _, l := range lines {
			t := strings.TrimSpace(l.Text)
			if m := stackStepRe.FindStringSubmatch(t); m != nil {
				d := "re-déploiement par Portainer, téléchargement des images"
				if j.DryRun {
					d = "stack relue, aucun re-déploiement"
				}
				steps = append(steps, stepView{Label: upperFirst(m[1]), Detail: d, Start: "stack n° " + m[2] + " (", Done: "stack re-déployée|re-déploiement non lancé"})
			} else if m := composeStepRe.FindStringSubmatch(t); m != nil {
				d := "docker compose pull puis up -d"
				if j.DryRun {
					d = "docker compose config, sans pull ni up"
				}
				steps = append(steps, stepView{Label: upperFirst(m[1]), Detail: d, Start: fmt.Sprintf("-docker-compose %d %s ", j.Target.VMID, m[2])})
			}
		}
		if !j.DryRun {
			steps = append(steps, stepView{Label: "Vérification", Detail: "détection, services et conteneurs comparés à l'état d'avant", Start: "▶ lxc-detect"})
		}
	case jobs.KindCycle:
		steps = append(steps,
			stepView{Label: "Démarrage", Detail: "invité arrêté démarré", Start: "▶ lxc-start", Done: "état après : running"},
			stepView{Label: "Détection", Detail: "plan établi sur une détection du jour", Start: "▶ lxc-detect", Done: "pw.end=1"},
			stepView{Label: "Mise à jour", Detail: map[bool]string{true: "simulation", false: "apt, puis vérification"}[j.DryRun], Start: "▶ lxc-apt|▶ lxc-snapshot", Done: "pw.apt_rc="},
			stepView{Label: "Arrêt", Detail: "arrêt propre, même en cas d'échec", Start: "▶ lxc-shutdown", Done: "état après : stopped"},
		)
	case jobs.KindRollback:
		steps = append(steps,
			stepView{Label: "Retour au snapshot", Detail: "CT arrêté puis restauré (pct rollback)", Start: "▶ lxc-rollback", Done: "terminé"},
			stepView{Label: "Redémarrage", Detail: "s'il tournait avant", Start: "PW: redémarrage du CT|PW: état après", Done: "PW: état après"},
			stepView{Label: "Vérification", Detail: "détection après le retour arrière", Start: "▶ lxc-detect", Done: "pw.end=1"},
		)
	case jobs.KindServices:
		steps = append(steps,
			stepView{Label: "Redémarrage des services", Detail: "systemctl restart, services système exclus", Start: "▶ lxc-restart-services", Done: "pw.restarted="},
			stepView{Label: "Vérification", Detail: "détection, services et conteneurs comparés à l'état d'avant", Start: "▶ lxc-detect"},
		)
	case jobs.KindReboot:
		steps = append(steps,
			stepView{Label: "Redémarrage du CT", Detail: "pct reboot", Start: "▶ lxc-reboot", Done: "PW: état après"},
			stepView{Label: "Vérification", Detail: "détection, services et conteneurs comparés à l'état d'avant", Start: "▶ lxc-detect"},
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

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func hasAny(text, markers string) bool {
	// Les marqueurs sont écrits pour les CT : une VM a les mêmes verbes en vm-.
	text = strings.Replace(text, "▶ vm-", "▶ lxc-", 1)
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
