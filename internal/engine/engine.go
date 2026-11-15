// Package engine relie l'inventaire, l'exécution SSH, les tâches et la
// détection : c'est lui qui construit le travail de chaque tâche.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/cs"
	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/notify"
	"github.com/LuckyS7evin/patchwarden/internal/sshx"
	"github.com/LuckyS7evin/patchwarden/internal/upstream"
)

// Engine porte les dépendances.
type Engine struct {
	Runner     sshx.Runner // nil : SSH non configuré (lecture seule)
	HasNode    func(string) bool
	Jobs       *jobs.Manager
	Store      *detect.Store
	Scripts    *cs.Fetcher
	Upstream   *upstream.Client
	Website    string
	AptRefresh bool
	Timeout    time.Duration
	Log        *slog.Logger
	Answers    *AnswerStore
	// SelfGuest (« nœud/vmid ») ou, à défaut, Hostname : invité hébergeant PatchWarden.
	SelfGuest string
	Hostname  string
	// Notify (facultatif) et PublicURL : notifications et liens.
	Notify    *notify.Hub
	PublicURL string
	// Snap : section [snapshots] ; SnapPrefs : réglage propre à chaque invité.
	Snap      SnapConfig
	SnapPrefs *PrefStore
	// Batches : lots d'opérations (facultatif).
	Batches *BatchStore
}

// Erreurs de refus, affichées telles quelles dans l'interface.
var (
	ErrNoSSH       = errors.New("accès SSH non configuré : PatchWarden est en lecture seule (section [ssh])")
	ErrNodeNoSSH   = errors.New("nœud absent de [ssh.nodes]")
	ErrNotLXC      = errors.New("la détection des VM arrive dans un prochain jalon")
	ErrStopped     = errors.New("invité arrêté : ignoré (aucune action sur les invités arrêtés)")
	ErrUnknown     = errors.New("état inconnu : le nœud ne publie pas l'état de ses invités (vérifiez pvestatd sur le nœud)")
	ErrTemplate    = errors.New("modèle : aucune action")
	ErrStaleNode   = errors.New("nœud injoignable lors du dernier inventaire")
	exitRefused    = 2
	exitNotRunning = 3
	exitBusy       = 99
)

// WrapperVersion est la version du wrapper attendue sur les nœuds.
const WrapperVersion = 7

// CanDetect dit si une détection est possible sur cet invité, et sinon pourquoi.
func (e *Engine) CanDetect(g inventory.Guest) error {
	switch {
	case e.Runner == nil:
		return ErrNoSSH
	case g.Template:
		return ErrTemplate
	case g.Type != "lxc":
		return ErrNotLXC
	case g.Status == "unknown" || g.Status == "":
		return ErrUnknown
	case g.Status != "running":
		return ErrStopped
	case g.Stale:
		return ErrStaleNode
	case e.HasNode != nil && !e.HasNode(g.Node):
		return fmt.Errorf("%w (%s)", ErrNodeNoSSH, g.Node)
	}
	return nil
}

func target(g inventory.Guest) jobs.Target {
	return jobs.Target{Node: g.Node, VMID: g.VMID, Type: g.Type, Name: g.Name}
}

// Detect met en file une détection pour un invité.
func (e *Engine) Detect(g inventory.Guest, user string) (jobs.Job, error) {
	if err := e.CanDetect(g); err != nil {
		return jobs.Job{}, err
	}
	return e.Jobs.Submit(jobs.KindDetect, target(g), false, user, e.detectFunc(g))
}

// DetectAll lance la détection sur tous les invités éligibles et renvoie le
// nombre de tâches créées et le nombre d'invités ignorés.
func (e *Engine) DetectAll(guests []inventory.Guest, user string) (started, skipped int) {
	for _, g := range guests {
		if _, err := e.Detect(g, user); err != nil {
			skipped++
			continue
		}
		started++
	}
	return started, skipped
}

func (e *Engine) detectFunc(g inventory.Guest) jobs.Func {
	return func(ctx context.Context, job jobs.Job, log jobs.Logger) (string, error) {
		res, err := e.detectRun(ctx, g, job.ID, log)
		if err != nil {
			return "", err
		}
		return summarize(res), nil
	}
}

// detectRun exécute la détection complète d'un invité et enregistre le résultat.
func (e *Engine) detectRun(ctx context.Context, g inventory.Guest, jobID string, log jobs.Logger) (detect.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	refresh := "0"
	if e.AptRefresh {
		refresh = "1"
	}
	cmd := fmt.Sprintf("lxc-detect %d %s", g.VMID, refresh)
	log(false, fmt.Sprintf("▶ %s · CT %d (%s) sur %s", cmd, g.VMID, g.Name, g.Node))
	if e.AptRefresh {
		log(false, "  (apt-get update est lancé dans l'invité : il rafraîchit l'index des paquets, sans rien installer)")
	}
	out, errs, code, err := e.run(ctx, g.Node, cmd, log)
	if err != nil {
		return detect.Result{}, err
	}
	if err := explainExit(code, errs); err != nil {
		return detect.Result{}, err
	}
	res, err := detect.Parse(out)
	if err != nil {
		return detect.Result{}, err
	}
	res.At, res.JobID = time.Now(), jobID
	e.enrichCS(ctx, g, &res, log)

	key := target(g).Key()
	if err := e.Store.Put(key, res); err != nil {
		e.Log.Error("enregistrement de la détection", "invité", key, "erreur", err)
	}
	return res, nil
}

// run exécute un verbe et renvoie stdout, stderr et le code de sortie, tout en
// journalisant chaque ligne.
func (e *Engine) run(ctx context.Context, node, cmd string, log jobs.Logger) (out, errs []string, code int, err error) {
	code, err = e.Runner.Run(ctx, node, cmd, func(l sshx.Line) {
		log(l.Stderr, l.Text)
		if l.Stderr {
			errs = append(errs, l.Text)
		} else {
			out = append(out, l.Text)
		}
	})
	return out, errs, code, err
}

func explainExit(code int, errs []string) error {
	last := ""
	if len(errs) > 0 {
		last = errs[len(errs)-1]
	}
	switch code {
	case 0:
		return nil
	case exitRefused:
		if strings.Contains(last, "verbe inconnu") {
			return fmt.Errorf("wrapper du nœud trop ancien (%s) : installez la version %d, voir README", strings.TrimPrefix(last, "PW-REFUS: "), WrapperVersion)
		}
		return fmt.Errorf("refusé par le wrapper du nœud : %s", strings.TrimPrefix(last, "PW-REFUS: "))
	case exitBusy:
		return errors.New("une opération PatchWarden est déjà en cours sur ce CT (verrou du nœud)")
	case exitNotRunning:
		return ErrStopped
	case 124:
		return errors.New("délai dépassé dans l'invité")
	default:
		return fmt.Errorf("code de sortie %d : %s", code, last)
	}
}

// enrichCS complète le résultat avec le script community-scripts, les
// versions installées et les dernières versions publiées. Les erreurs sont
// journalisées et conservées, sans faire échouer la détection.
func (e *Engine) enrichCS(ctx context.Context, g inventory.Guest, res *detect.Result, log jobs.Logger) {
	c := &res.CS
	if !c.Present() {
		return
	}
	c.PageURL = cs.ScriptPageURL(e.Website, c.Slug)
	c.BaseAllowed = e.Scripts.Allowed(c.Base)
	if !c.BaseAllowed {
		c.Error = "source de scripts non autorisée : " + c.Base
		log(true, "⚠ "+c.Error+" (community_scripts.allowed_bases)")
		return
	}
	log(false, fmt.Sprintf("▶ analyse du script ct/%s.sh", c.Script))
	sc, err := e.Scripts.Get(ctx, c.Base, c.Script)
	if err != nil {
		c.Error = err.Error()
		log(true, "⚠ "+c.Error)
		return
	}
	c.ScriptURL, c.NeedCPU, c.NeedRAMMB, c.Prompts, c.OSOnly = sc.URL, sc.NeedCPU, sc.NeedRAMMB, sc.Prompts, sc.OSOnly
	if c.NeedCPU > 0 && (res.Nproc < c.NeedCPU || res.MemMB < c.NeedRAMMB) {
		log(false, fmt.Sprintf("  ressources : le script demande %d CPU / %d Mo, le CT a %d CPU / %d Mo (augmentation temporaire nécessaire à la mise à jour)", c.NeedCPU, c.NeedRAMMB, res.Nproc, res.MemMB))
	}
	for _, p := range c.Prompts {
		log(false, "  question posée sans terminal par le script : « "+p+" »")
	}
	if c.OSOnly {
		log(false, "  le script ne met à jour que l'OS (apt), pas l'application")
	}
	if len(sc.Apps) == 0 {
		return
	}

	names := make([]string, 0, len(sc.Apps))
	for _, a := range sc.Apps {
		names = append(names, a.VersionFile())
	}
	cmd := "lxc-versions " + strconv.Itoa(g.VMID) + " " + strings.Join(names, " ")
	log(false, "▶ "+cmd)
	out, errs, code, err := e.run(ctx, g.Node, cmd, log)
	if err == nil {
		err = explainExit(code, errs)
	}
	installed, absent := detect.ParseVersions(out)
	if err != nil {
		log(true, "⚠ lecture des versions installées : "+err.Error())
	}

	for _, a := range sc.Apps {
		app := detect.App{Name: a.Name, Forge: a.Forge, Repo: a.Repo, Kind: a.Kind}
		if v, ok := installed[a.VersionFile()]; ok {
			app.Installed, app.InstalledKnown = v, true
		} else if absent[a.VersionFile()] {
			app.Installed = "fichier /root/." + a.VersionFile() + " absent"
		}
		switch {
		case a.Kind == "branch":
			app.LatestError = "suivie par branche (" + a.Branch + ") : pas de numéro de version"
			app.ChangelogURL = forgeWeb(a) + "/commits/" + a.Branch
		case a.Pinned != "":
			app.Latest = a.Pinned
			app.ChangelogURL = forgeWeb(a) + "/releases"
			log(false, fmt.Sprintf("  %s : version imposée par le script : %s", a.Name, a.Pinned))
		default:
			r, err := e.Upstream.Latest(ctx, upstream.Query{Forge: a.Forge, Host: a.Host, Repo: a.Repo, Kind: a.Kind, Prefix: a.Prefix, Pre: a.Pre})
			if err != nil {
				app.LatestError = err.Error()
				app.ChangelogURL = forgeWeb(a) + "/releases"
			} else {
				app.Latest, app.ChangelogURL = r.Tag, r.ChangelogURL
			}
		}
		line := fmt.Sprintf("  %s (%s) : installée %s · dernière %s → %s", a.Name, a.Repo, orDash(app.Installed), orDash(app.Latest), app.Status())
		if app.LatestError != "" {
			line += " (" + app.LatestError + ")"
		}
		log(false, line)
		res.Apps = append(res.Apps, app)
	}
}

func forgeWeb(a cs.App) string {
	switch a.Forge {
	case "codeberg":
		return "https://codeberg.org/" + a.Repo
	case "gitlab":
		h := a.Host
		if h == "" {
			h = "gitlab.com"
		}
		return "https://" + h + "/" + a.Repo + "/-"
	default:
		return "https://github.com/" + a.Repo
	}
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func summarize(r detect.Result) string {
	var parts []string
	if r.Apt.Present {
		if r.Apt.Total == 0 {
			parts = append(parts, "apt à jour")
		} else {
			parts = append(parts, fmt.Sprintf("%d paquet(s) dont %d de sécurité", r.Apt.Total, r.Apt.Security))
		}
	}
	for _, a := range r.Apps {
		if a.UpdateAvailable() {
			parts = append(parts, fmt.Sprintf("%s %s → %s", a.Name, a.Installed, a.Latest))
		}
	}
	if r.RebootRequired {
		parts = append(parts, "redémarrage requis")
	}
	if n := len(r.RestartUnits); n > 0 {
		parts = append(parts, plural(n, "service lié à d'anciennes bibliothèques", "services liés à d'anciennes bibliothèques"))
	}
	if len(parts) == 0 {
		return "rien à signaler"
	}
	return strings.Join(parts, " · ")
}
