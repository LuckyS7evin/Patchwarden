package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
)

// SnapConfig reprend la section [snapshots] de la configuration.
type SnapConfig struct {
	Default bool // case cochée par défaut pour tous les invités
	Keep    int  // snapshots PatchWarden gardés par invité
	MaxPct  int  // seuil de remplissage du stockage
}

// Réglage « snapshot avant mise à jour » propre à un invité.
const (
	PrefAuto   = ""         // réglage global et règles automatiques
	PrefAlways = "toujours" // toujours cochée
	PrefNever  = "jamais"   // jamais cochée d'office (on peut encore la cocher)
)

// SnapPlan décrit le snapshot proposé avant une mise à jour.
type SnapPlan struct {
	Possible bool
	Why      string // raison si impossible
	Checked  bool   // case pré-cochée
	Reason   string // pourquoi elle l'est (ou non)
	Name     string // nom prévu (horodaté au lancement)
	Storage  string // « local-lvm (lvmthin) : 45 % »
	Binds    int
	// Removed : snapshots PatchWarden supprimés par la rétention après création.
	Removed []string
}

var pwSnapRe = regexp.MustCompile(`^pw-[0-9]{8}-[0-9]{4}-(complet|securite|docker)$`)

// ValidSnapName dit si un nom est celui d'un snapshot PatchWarden.
func ValidSnapName(n string) bool { return pwSnapRe.MatchString(n) }

func snapName(t time.Time, a Action) string {
	return "pw-" + t.Local().Format("20060102-1504") + "-" + string(a)
}

func (e *Engine) snapConfig() SnapConfig {
	c := e.Snap
	if c.Keep < 1 {
		c.Keep = 1
	}
	if c.MaxPct < 1 {
		c.MaxPct = 90
	}
	return c
}

// planSnapshot remplit p.Snap à partir de la dernière détection.
func (e *Engine) planSnapshot(p *Plan, det detect.Result) {
	cfg := e.snapConfig()
	sp := SnapPlan{Name: snapName(time.Now(), p.Action), Binds: det.Snap.Binds}
	major := false
	if p.Action == ActFull && p.CSRun {
		for _, a := range det.Apps {
			if a.MajorChange() {
				major = true
			}
		}
	}
	pref := ""
	if e.SnapPrefs != nil {
		pref = e.SnapPrefs.Get(target(p.Guest).Key())
	}
	switch {
	case pref == PrefNever:
		sp.Reason = "réglage de l'invité : jamais d'office"
	case pref == PrefAlways:
		sp.Checked, sp.Reason = true, "réglage de l'invité : toujours"
	case cfg.Default:
		sp.Checked, sp.Reason = true, "réglage global ([snapshots] default)"
	case p.Guest.Critical:
		sp.Checked, sp.Reason = true, "invité critique ("+p.Guest.CriticalReason+")"
	case major:
		sp.Checked, sp.Reason = true, "changement de version majeure"
	default:
		sp.Reason = "décochée par défaut"
	}

	s := det.Snap
	var parts []string
	for _, st := range s.Storages {
		if st.UsedPct < 0 {
			parts = append(parts, fmt.Sprintf("%s (%s) : remplissage inconnu", st.Name, st.Type))
		} else {
			parts = append(parts, fmt.Sprintf("%s (%s) : %.0f %%", st.Name, st.Type, st.UsedPct))
		}
	}
	sp.Storage = strings.Join(parts, " · ")
	switch full, ok := s.Fullest(); {
	case !s.Known:
		sp.Why = "informations de snapshot absentes : relancez une détection (wrapper v5 requis sur le nœud)"
	case !s.Possible:
		sp.Why = "le stockage de ce CT ne permet pas les snapshots (" + sp.Storage + ") ; stockages compatibles : LVM-thin, ZFS, Ceph RBD, Btrfs"
	case !ok:
		sp.Why = "aucun stockage trouvé pour ce CT"
	case full.UsedPct < 0:
		sp.Why = "remplissage du stockage " + full.Name + " inconnu"
	case full.UsedPct >= float64(cfg.MaxPct):
		sp.Why = fmt.Sprintf("stockage %s rempli à %.0f %% (seuil : %d %%)", full.Name, full.UsedPct, cfg.MaxPct)
	default:
		sp.Possible = true
	}

	names := make([]string, 0, len(s.PW))
	for _, sn := range s.PW {
		names = append(names, sn.Name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) >= cfg.Keep {
		sp.Removed = names[cfg.Keep-1:]
	}
	if sp.Checked && !sp.Possible {
		p.Warnings = append(p.Warnings, "snapshot souhaité ("+sp.Reason+") mais impossible : "+sp.Why+". Sans snapshot, assurez-vous d'avoir une sauvegarde récente")
	}
	p.Snap = sp
}

// snapDescription compose la description du snapshot (300 octets au plus).
func snapDescription(p Plan, user string, at time.Time) string {
	d := fmt.Sprintf("PatchWarden avant « %s » le %s par %s", p.Action.Label(), at.Local().Format("02/01/2006 15:04"), user)
	if p.Det != nil && p.Action != ActDocker {
		if p.Action == ActSecurity {
			d += fmt.Sprintf(" ; apt : %d paquet(s) de sécurité", p.Det.Apt.SecurityStrict)
		} else {
			d += fmt.Sprintf(" ; apt : %d paquet(s)", p.Det.Apt.Total)
		}
	}
	if p.CSRun && p.CSNote != "" {
		d += " ; " + p.CSNote
	}
	for len(d) > 300 {
		_, size := utf8.DecodeLastRuneInString(d)
		d = d[:len(d)-size]
	}
	return d
}

// takeSnapshot crée (ou vérifie, en simulation) le snapshot d'avant mise à jour.
func (e *Engine) takeSnapshot(ctx context.Context, p Plan, dryRun bool, user string, log jobs.Logger) (string, error) {
	g, cfg, now := p.Guest, e.snapConfig(), time.Now()
	name := snapName(now, p.Action)
	desc := base64.RawURLEncoding.EncodeToString([]byte(snapDescription(p, user, now)))
	dry := "0"
	if dryRun {
		dry = "1"
	}
	v := verb(g, "snapshot")
	cmd := fmt.Sprintf("%s %d %s %d %d %s %s", v, g.VMID, name, cfg.Keep, cfg.MaxPct, dry, desc)
	log(false, fmt.Sprintf("▶ %s %d %s %d %d %s <description>", v, g.VMID, name, cfg.Keep, cfg.MaxPct, dry))
	out, errs, code, err := e.run(ctx, g.Node, cmd, log)
	if err != nil {
		return name, connLost(err, out)
	}
	if err := explainSnap(code, errs, out); err != nil {
		return name, err
	}
	if info, ok := detect.ParseSnap(out); ok && !dryRun {
		if err := e.Store.UpdateSnap(target(g).Key(), info); err != nil {
			e.Log.Warn("enregistrement des snapshots", "invité", g.Key(), "erreur", err)
		}
	}
	return name, nil
}

func explainSnap(code int, errs, out []string) error {
	switch code {
	case 0:
		return nil
	case 40, 41, 42, 43, 44, 45, 46:
		msg := strings.TrimPrefix(lastMatching(out, "PW-ERREUR: "), "PW-ERREUR: ")
		return fmt.Errorf("%s (code %d)", msg, code)
	}
	return explainExit(code, errs)
}

// CanSnapAction dit si un retour arrière ou une suppression de snapshot est
// possible sur cet invité (démarré ou non).
func (e *Engine) CanSnapAction(g inventory.Guest) error {
	switch {
	case e.Runner == nil:
		return ErrNoSSH
	case g.Template:
		return ErrTemplate
	case g.Type != "lxc" && g.Type != "qemu":
		return ErrNotLXC
	case g.Stale:
		return ErrStaleNode
	case e.HasNode != nil && !e.HasNode(g.Node):
		return fmt.Errorf("%w (%s)", ErrNodeNoSSH, g.Node)
	case e.IsSelf(g):
		return errors.New("cet invité héberge PatchWarden : un retour arrière lancé d'ici l'arrêterait en cours de route ; faites-le depuis Proxmox")
	}
	return nil
}

func (e *Engine) knownSnapshot(g inventory.Guest, name string) (detect.Snapshot, error) {
	if !ValidSnapName(name) {
		return detect.Snapshot{}, fmt.Errorf("%q n'est pas un snapshot PatchWarden", name)
	}
	det, ok := e.Store.Get(target(g).Key())
	if !ok {
		return detect.Snapshot{}, errors.New("aucune détection : relancez-la pour lister les snapshots")
	}
	sn, ok := det.Snap.Has(name)
	if !ok {
		return detect.Snapshot{}, fmt.Errorf("snapshot %s inconnu : relancez une détection", name)
	}
	return sn, nil
}

// Rollback ramène un CT à un snapshot PatchWarden. typedName : nom de
// l'invité saisi pour confirmer (toujours exigé).
func (e *Engine) Rollback(g inventory.Guest, name, user, typedName string) (jobs.Job, error) {
	if err := e.CanSnapAction(g); err != nil {
		return jobs.Job{}, err
	}
	if _, err := e.knownSnapshot(g, name); err != nil {
		return jobs.Job{}, err
	}
	if strings.TrimSpace(typedName) != g.Name {
		return jobs.Job{}, fmt.Errorf("%w : saisissez exactement le nom de l'invité (%s)", ErrConfirm, g.Name)
	}
	return e.Jobs.Submit(jobs.KindRollback, target(g), false, user, func(ctx context.Context, job jobs.Job, log jobs.Logger) (string, error) {
		cmd := fmt.Sprintf("%s %d %s", verb(g, "rollback"), g.VMID, name)
		log(false, fmt.Sprintf("Retour du CT %d (%s) sur %s au snapshot %s", g.VMID, g.Name, g.Node, name))
		log(false, "▶ "+cmd)
		out, errs, code, err := e.run(ctx, g.Node, cmd, log)
		if err != nil {
			return "", connLost(err, out)
		}
		if info, ok := detect.ParseSnap(out); ok {
			_ = e.Store.UpdateSnap(target(g).Key(), info)
		}
		if err := explainSnap(code, errs, out); err != nil {
			return "", err
		}
		summary := "retour au snapshot " + name
		running := false
		for _, l := range out {
			if v, ok := strings.CutPrefix(l, "PW: état après : "); ok {
				summary += " · état : " + v
				running = v == "running"
			}
		}
		if running {
			log(false, "")
			if res, err := e.detectRun(ctx, g, job.ID, log); err != nil {
				log(true, "⚠ détection après le retour arrière impossible : "+err.Error())
			} else {
				summary += " · après : " + summarize(res)
			}
		}
		return summary, nil
	})
}

// DeleteSnapshot supprime un snapshot PatchWarden.
func (e *Engine) DeleteSnapshot(g inventory.Guest, name, user string, confirmed bool) (jobs.Job, error) {
	if err := e.CanSnapAction(g); err != nil {
		return jobs.Job{}, err
	}
	if _, err := e.knownSnapshot(g, name); err != nil {
		return jobs.Job{}, err
	}
	if !confirmed {
		return jobs.Job{}, fmt.Errorf("%w : cochez la case de confirmation", ErrConfirm)
	}
	return e.Jobs.Submit(jobs.KindSnapDelete, target(g), false, user, func(ctx context.Context, _ jobs.Job, log jobs.Logger) (string, error) {
		cmd := fmt.Sprintf("%s %d %s", verb(g, "snapdel"), g.VMID, name)
		log(false, "▶ "+cmd)
		out, errs, code, err := e.run(ctx, g.Node, cmd, log)
		if err != nil {
			return "", connLost(err, out)
		}
		if info, ok := detect.ParseSnap(out); ok {
			_ = e.Store.UpdateSnap(target(g).Key(), info)
		}
		if err := explainSnap(code, errs, out); err != nil {
			return "", err
		}
		return "snapshot " + name + " supprimé", nil
	})
}

// SnapPref renvoie le réglage de snapshot d'un invité.
func (e *Engine) SnapPref(key string) string {
	if e.SnapPrefs == nil {
		return PrefAuto
	}
	return e.SnapPrefs.Get(key)
}

// SetSnapPref enregistre le réglage de snapshot d'un invité.
func (e *Engine) SetSnapPref(key, v string) error {
	if v != PrefAuto && v != PrefAlways && v != PrefNever {
		return fmt.Errorf("réglage inconnu : %q", v)
	}
	if e.SnapPrefs == nil {
		return errors.New("réglages des invités indisponibles")
	}
	return e.SnapPrefs.Set(key, v)
}

// SnapDefaults renvoie la configuration globale des snapshots.
func (e *Engine) SnapDefaults() SnapConfig { return e.snapConfig() }

// PrefStore conserve un réglage texte par invité, sur disque.
type PrefStore struct {
	path string
	mu   sync.Mutex
	m    map[string]string
}

// OpenPrefs charge (ou crée) le fichier de réglages name dans dir.
func OpenPrefs(dir, name string) (*PrefStore, error) {
	s := &PrefStore{path: filepath.Join(dir, name), m: map[string]string{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, &s.m)
}

// Get renvoie le réglage d'un invité ("" s'il n'en a pas).
func (s *PrefStore) Get(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key]
}

// Set enregistre le réglage d'un invité ("" l'efface).
func (s *PrefStore) Set(key, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v == "" {
		delete(s.m, key)
	} else {
		s.m[key] = v
	}
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
