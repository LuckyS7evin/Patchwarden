package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

// Action est une mise à jour demandée par l'utilisateur.
type Action string

// Actions possibles.
const (
	ActSecurity Action = "securite"
	ActFull     Action = "complet"
)

// ParseAction valide une action venue de l'interface.
func ParseAction(s string) (Action, error) {
	switch Action(s) {
	case ActSecurity, ActFull:
		return Action(s), nil
	}
	return "", fmt.Errorf("action inconnue : %q", s)
}

// Kind renvoie le type de tâche correspondant.
func (a Action) Kind() jobs.Kind {
	if a == ActSecurity {
		return jobs.KindSecurity
	}
	return jobs.KindFull
}

// Label renvoie le libellé affiché.
func (a Action) Label() string { return string(a.Kind()) }

// MaxDetectionAge : au-delà, une nouvelle détection est exigée avant d'agir.
const MaxDetectionAge = 24 * time.Hour

// PromptAnswer associe une question du script à la réponse enregistrée.
type PromptAnswer struct {
	Prompt string
	Value  string // "y", "n" ou "" (Entrée : réponse par défaut)
	Set    bool
}

// Plan décrit ce qu'une action ferait sur un invité, avant toute confirmation.
type Plan struct {
	Action   Action
	Guest    inventory.Guest
	Det      *detect.Result
	Steps    []string
	Warnings []string
	// Blockers empêchent l'action (simulation comprise).
	Blockers []string
	Packages []detect.Package
	// CSRun : la commande update community-scripts sera lancée.
	CSRun   bool
	CSNote  string
	Answers []PromptAnswer
	// NeedCPU/NeedRAM : minimum exigé par le script, transmis au wrapper qui
	// augmente puis restaure les ressources si le CT est en dessous.
	NeedCPU, NeedRAM int
	Bump             bool
	// NeedName : invité critique, le nom doit être saisi pour confirmer.
	NeedName bool
}

// OK indique que l'action est possible.
func (p Plan) OK() bool { return len(p.Blockers) == 0 }

// IsSelf indique si l'invité héberge PatchWarden.
func (e *Engine) IsSelf(g inventory.Guest) bool {
	if e.SelfGuest != "" {
		return g.Key() == e.SelfGuest
	}
	return e.Hostname != "" && strings.EqualFold(g.Name, e.Hostname)
}

// PlanFor construit le plan d'une action sur un invité.
func (e *Engine) PlanFor(g inventory.Guest, a Action) Plan {
	p := Plan{Action: a, Guest: g, NeedName: g.Critical}
	if err := e.CanDetect(g); err != nil {
		p.Blockers = append(p.Blockers, err.Error())
		return p
	}
	if e.IsSelf(g) {
		p.Blockers = append(p.Blockers, "cet invité héberge PatchWarden : une mise à jour lancée d'ici couperait PatchWarden en cours de route. Lancez-la à la main (update, apt) ou depuis une autre instance (policy.self_guest)")
		return p
	}
	det, ok := e.Store.Get(target(g).Key())
	if !ok {
		p.Blockers = append(p.Blockers, "aucune détection : lancez d'abord « Détecter les mises à jour »")
		return p
	}
	p.Det = &det
	if age := time.Since(det.At); age > MaxDetectionAge {
		p.Blockers = append(p.Blockers, fmt.Sprintf("dernière détection trop ancienne (%s) : relancez-la", age.Round(time.Hour)))
	}
	if !det.Apt.Present {
		p.Blockers = append(p.Blockers, "apt absent de cet invité : seules les distributions Debian/Ubuntu sont prises en charge pour l'instant")
		return p
	}

	switch a {
	case ActSecurity:
		if !det.Apt.SecurityRepo {
			p.Blockers = append(p.Blockers, "aucun dépôt de sécurité configuré dans cet invité")
		}
		strict := map[string]bool{}
		for _, n := range det.Apt.StrictPackages {
			strict[n] = true
		}
		for _, pk := range det.Apt.Packages {
			if strict[pk.Name] {
				p.Packages = append(p.Packages, pk)
			}
		}
		if det.Apt.SecurityStrict == 0 {
			p.Blockers = append(p.Blockers, "aucune mise à jour de sécurité à appliquer")
		}
		p.Steps = append(p.Steps,
			"apt-get update (index complet)",
			fmt.Sprintf("apt-get --with-new-pkgs upgrade limité aux dépôts *-security : %d paquet(s)", det.Apt.SecurityStrict))
		if miss := det.Apt.Security - det.Apt.SecurityStrict; miss > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%d correctif(s) de sécurité dépendent d'un paquet hors dépôt de sécurité : seul « Tout mettre à jour » les installera", miss))
		}
	case ActFull:
		p.Packages = det.Apt.Packages
		p.Steps = append(p.Steps,
			"apt-get update",
			fmt.Sprintf("apt-get --with-new-pkgs upgrade : %d paquet(s), dont %d de sécurité (aucune suppression)", det.Apt.Total, det.Apt.Security))
		if det.Apt.DistTotal > det.Apt.Total {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%d paquet(s) ne passent qu'avec un dist-upgrade (qui peut supprimer des paquets) : non appliqués", det.Apt.DistTotal-det.Apt.Total))
		}
		e.planCS(&p, det)
		if det.Apt.Total == 0 && !p.CSRun {
			p.Blockers = append(p.Blockers, "rien à mettre à jour")
		}
	}

	if det.RootUsedPct >= 90 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("disque / plein à %d %% : apt peut échouer faute de place", det.RootUsedPct))
	}
	if det.RebootRequired {
		p.Warnings = append(p.Warnings, "un redémarrage de l'invité est déjà requis (mise à jour précédente)")
	}
	if g.Critical {
		p.Warnings = append(p.Warnings, "invité critique ("+g.CriticalReason+") : saisissez son nom pour confirmer")
	}
	p.Steps = append(p.Steps, "détection après la mise à jour, pour vérifier le résultat")
	return p
}

func (e *Engine) planCS(p *Plan, det detect.Result) {
	c := det.CS
	switch {
	case !c.Present():
		return
	case c.Error != "":
		p.CSNote = "update community-scripts non lancé : " + c.Error
		p.Warnings = append(p.Warnings, p.CSNote)
		return
	case c.OSOnly:
		p.CSNote = "le script ct/" + c.Script + ".sh ne fait qu'une mise à jour apt, déjà couverte : update non lancé"
		return
	}
	var pending, unknown []string
	for _, a := range det.Apps {
		switch a.Status() {
		case "mise à jour disponible":
			pending = append(pending, fmt.Sprintf("%s %s → %s", a.Name, a.Installed, a.Latest))
		case "inconnue":
			unknown = append(unknown, a.Name)
		}
	}
	switch {
	case len(det.Apps) == 0:
		p.CSRun = true
		p.CSNote = "le script ne publie pas de numéro de version : update est lancé pour vérifier"
	case len(pending) > 0:
		p.CSRun = true
		p.CSNote = strings.Join(pending, " · ")
	case len(unknown) > 0:
		p.CSRun = true
		p.CSNote = "version inconnue pour " + strings.Join(unknown, ", ") + " : update est lancé pour vérifier"
	default:
		p.CSNote = "applications à jour : update community-scripts non lancé"
		return
	}
	p.Steps = append(p.Steps, "update community-scripts (ct/"+c.Script+".sh), sans terminal : "+p.CSNote)

	p.NeedCPU, p.NeedRAM = c.NeedCPU, c.NeedRAMMB
	if (c.NeedCPU > 0 && det.Nproc < c.NeedCPU) || (c.NeedRAMMB > 0 && det.MemMB < c.NeedRAMMB) {
		p.Bump = true
		p.Steps = append(p.Steps, fmt.Sprintf("ressources portées temporairement de %d CPU / %d Mo à %d CPU / %d Mo pendant update, puis restaurées (même en cas d'échec)",
			det.Nproc, det.MemMB, max(det.Nproc, c.NeedCPU), max(det.MemMB, c.NeedRAMMB)))
	}
	if det.RootUsedPct >= 80 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("disque / plein à %d %% : le moteur community-scripts refusera la mise à jour au-delà de 80 %% (code 114)", det.RootUsedPct))
	}
	if len(c.Prompts) > 0 {
		saved := e.Answers.Get(target(p.Guest).Key())
		missing := false
		for _, q := range c.Prompts {
			v, ok := saved[q]
			p.Answers = append(p.Answers, PromptAnswer{Prompt: q, Value: v, Set: ok})
			if !ok {
				missing = true
			}
		}
		if missing {
			p.Blockers = append(p.Blockers, "le script pose des questions sans terminal : enregistrez une réponse pour chacune (page de l'invité)")
		}
	}
}

// answersArg encode les réponses pour le wrapper : « - » ou y/n/_ séparés par des points.
func answersArg(ans []PromptAnswer) string {
	if len(ans) == 0 {
		return "-"
	}
	parts := make([]string, len(ans))
	for i, a := range ans {
		switch a.Value {
		case "y", "n":
			parts[i] = a.Value
		default:
			parts[i] = "_"
		}
	}
	return strings.Join(parts, ".")
}

// ErrConfirm : la confirmation saisie ne correspond pas.
var ErrConfirm = errors.New("confirmation manquante ou incorrecte")

// Execute lance une action (ou sa simulation) après vérification du plan.
// confirmed : case de confirmation cochée ; typedName : nom saisi (invités critiques).
func (e *Engine) Execute(g inventory.Guest, a Action, dryRun bool, user string, confirmed bool, typedName string) (jobs.Job, error) {
	p := e.PlanFor(g, a)
	if !p.OK() {
		return jobs.Job{}, errors.New(p.Blockers[0])
	}
	if !dryRun {
		if !confirmed {
			return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
		}
		if p.NeedName && strings.TrimSpace(typedName) != g.Name {
			return jobs.Job{}, fmt.Errorf("%w : saisissez exactement le nom de l'invité (%s)", ErrConfirm, g.Name)
		}
	}
	return e.Jobs.Submit(a.Kind(), target(g), dryRun, user, e.updateFunc(p, dryRun))
}

func (e *Engine) updateFunc(p Plan, dryRun bool) jobs.Func {
	g := p.Guest
	return func(ctx context.Context, job jobs.Job, log jobs.Logger) (string, error) {
		mode := "full"
		if p.Action == ActSecurity {
			mode = "security"
		}
		dry := "0"
		if dryRun {
			dry = "1"
			log(false, "SIMULATION : rien ne sera modifié dans l'invité")
		}
		log(false, fmt.Sprintf("Plan « %s » pour CT %d (%s) sur %s :", p.Action.Label(), g.VMID, g.Name, g.Node))
		for i, s := range p.Steps {
			log(false, fmt.Sprintf("  %d. %s", i+1, s))
		}
		for _, w := range p.Warnings {
			log(false, "  ⚠ "+w)
		}
		var summary []string

		// 1. apt
		cmd := fmt.Sprintf("lxc-apt %d %s %s", g.VMID, mode, dry)
		log(false, "▶ "+cmd)
		out, errs, code, err := e.run(ctx, g.Node, cmd, log)
		if err != nil {
			return "", connLost(err, out)
		}
		if err := explainApt(code, errs, out); err != nil {
			return "", err
		}
		n := aptCount(out)
		if dryRun {
			summary = append(summary, fmt.Sprintf("simulation apt : %d paquet(s)", n))
		} else {
			summary = append(summary, fmt.Sprintf("apt : %d paquet(s) mis à jour", n))
		}

		// 2. community-scripts
		if p.CSRun {
			if dryRun {
				log(false, "▶ update community-scripts : non exécuté en simulation (le script n'a pas de mode simulation)")
				log(false, "  serait lancé : "+p.CSNote)
				if p.Bump {
					log(false, fmt.Sprintf("  ressources portées temporairement à %d CPU / %d Mo puis restaurées", p.NeedCPU, p.NeedRAM))
				}
				for _, a := range p.Answers {
					log(false, fmt.Sprintf("  réponse à « %s » : %s", a.Prompt, answerLabel(a.Value)))
				}
				summary = append(summary, "update community-scripts simulé : "+p.CSNote)
			} else {
				cmd := fmt.Sprintf("lxc-cs-update %d %s %d %d", g.VMID, answersArg(p.Answers), p.NeedCPU, p.NeedRAM)
				log(false, "▶ "+cmd)
				out, errs, code, err := e.run(ctx, g.Node, cmd, log)
				if err != nil {
					return strings.Join(summary, " · "), connLost(err, out)
				}
				if err := explainCSUpdate(code, errs, out); err != nil {
					return strings.Join(summary, " · "), err
				}
				summary = append(summary, "update community-scripts : "+p.CSNote)
			}
		} else if p.CSNote != "" {
			log(false, "  "+p.CSNote)
		}

		// 3. vérification
		if !dryRun {
			log(false, "")
			res, err := e.detectRun(ctx, g, job.ID, log)
			if err != nil {
				log(true, "⚠ détection après mise à jour impossible : "+err.Error())
			} else {
				summary = append(summary, "après : "+summarize(res))
			}
		}
		return strings.Join(summary, " · "), nil
	}
}

func answerLabel(v string) string {
	switch v {
	case "y":
		return "oui"
	case "n":
		return "non"
	default:
		return "réponse par défaut (Entrée)"
	}
}

var aptSummaryRe = regexp.MustCompile(`^(\d+) upgraded, (\d+) newly installed`)

// aptCount lit le bilan d'apt (« N upgraded, M newly installed… », présent en
// simulation comme en exécution réelle, LC_ALL=C) ; à défaut, compte les
// lignes « Inst » de la simulation.
func aptCount(lines []string) int {
	inst := 0
	for i := len(lines) - 1; i >= 0; i-- {
		if m := aptSummaryRe.FindStringSubmatch(lines[i]); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			return a + b
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "Inst ") {
			inst++
		}
	}
	return inst
}

// connLost explique une coupure de connexion pendant une opération détachée.
func connLost(err error, out []string) error {
	for _, l := range out {
		if path, ok := strings.CutPrefix(l, "pw.node_log="); ok {
			return fmt.Errorf("%v : la connexion au nœud est perdue, mais l'opération continue sur le nœud ; journal complet : %s", err, path)
		}
	}
	return err
}

func explainApt(code int, errs, out []string) error {
	switch code {
	case 0:
		return nil
	case 21:
		return errors.New("aucun dépôt de sécurité configuré dans cet invité")
	case 100:
		return fmt.Errorf("apt a échoué (code 100) : %s", lastMatching(out, "E: "))
	}
	return explainExit(code, errs)
}

func explainCSUpdate(code int, errs, out []string) error {
	switch code {
	case 0:
		return nil
	case 113:
		return errors.New("update refusé par le script (code 113) : CPU/RAM insuffisants malgré l'augmentation temporaire")
	case 114:
		return errors.New("update refusé par le script (code 114) : disque / plein à plus de 80 %")
	case 75:
		return errors.New("update refusé par le script (code 75) : il exige un terminal interactif")
	case 30:
		return errors.New("/usr/bin/update absent de l'invité")
	case 31:
		return errors.New("augmentation temporaire des ressources impossible (pct set)")
	}
	if code != exitRefused && code != exitNotRunning && code != exitBusy && code != 124 {
		return fmt.Errorf("update a échoué (code %d) : %s", code, lastMatching(out, "[ERROR]", "✖", "✘", "Error", "error"))
	}
	return explainExit(code, errs)
}

func lastMatching(lines []string, subs ...string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		for _, s := range subs {
			if strings.Contains(lines[i], s) {
				return strings.TrimSpace(lines[i])
			}
		}
	}
	return "voir le journal"
}

// AnswerStore conserve, par invité, les réponses aux questions des scripts.
type AnswerStore struct {
	path string
	mu   sync.Mutex
	m    map[string]map[string]string
}

// OpenAnswers charge le fichier des réponses.
func OpenAnswers(dir string) (*AnswerStore, error) {
	s := &AnswerStore{path: filepath.Join(dir, "answers.json"), m: map[string]map[string]string{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, &s.m)
}

// Get renvoie une copie des réponses d'un invité.
func (s *AnswerStore) Get(key string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.m[key] {
		out[k] = v
	}
	return out
}

// Set remplace les réponses d'un invité. Valeurs admises : y, n ou "" (Entrée).
func (s *AnswerStore) Set(key string, answers map[string]string) error {
	for q, v := range answers {
		if v != "y" && v != "n" && v != "" {
			return fmt.Errorf("réponse invalide pour « %s » : %q", q, v)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = answers
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// VMIDKey compose la clé d'un invité (utile à l'interface).
func VMIDKey(node string, vmid int) string { return node + "/" + strconv.Itoa(vmid) }

// SetAnswers enregistre les réponses d'un invité aux questions de son script.
func (e *Engine) SetAnswers(key string, answers map[string]string) error {
	return e.Answers.Set(key, answers)
}
