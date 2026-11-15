// Package detect interprète la sortie de détection du wrapper et conserve le
// dernier résultat connu pour chaque invité.
package detect

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Package est un paquet apt à mettre à jour.
type Package struct {
	Name     string `json:"name"`
	Old      string `json:"old"` // "-" si le paquet est nouveau
	New      string `json:"new"`
	Security bool   `json:"security"`
	// Since : première détection où cette mise à jour (nom + nouvelle version)
	// était proposée ; conservée d'une détection à l'autre.
	Since time.Time `json:"since,omitempty"`
}

// App est une application suivie par un script community-scripts.
type App struct {
	Name           string `json:"name"`
	Forge          string `json:"forge"` // github, codeberg, gitlab
	Repo           string `json:"repo"`
	Kind           string `json:"kind"` // release ou tag
	Installed      string `json:"installed"`
	InstalledKnown bool   `json:"installed_known"`
	Latest         string `json:"latest"`
	LatestError    string `json:"latest_error,omitempty"`
	ChangelogURL   string `json:"changelog_url"`
	// Since : première détection où cette dernière version était disponible.
	Since time.Time `json:"since,omitempty"`
}

// Status résume la comparaison des versions.
func (a App) Status() string {
	switch {
	case !a.InstalledKnown || a.Latest == "":
		return "inconnue"
	case Normalize(a.Installed) == Normalize(a.Latest):
		return "à jour"
	default:
		return "mise à jour disponible"
	}
}

// UpdateAvailable indique qu'une version plus récente est publiée.
func (a App) UpdateAvailable() bool { return a.Status() == "mise à jour disponible" }

// Normalize rend deux tags comparables (« v1.2.3 » = « 1.2.3 »). Les formats
// très différents (« release-2.6.1-tag » contre « v26.11.1 ») restent
// différents : c'est voulu, l'amont a changé de schéma de version.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v
}

// CS décrit l'intégration community-scripts d'un LXC.
type CS struct {
	Entry       string   `json:"entry"` // helper, legacy, inconnu, aucune
	Script      string   `json:"script"`
	Slug        string   `json:"slug"`
	Base        string   `json:"base"`
	BaseAllowed bool     `json:"base_allowed"`
	ScriptURL   string   `json:"script_url,omitempty"`
	PageURL     string   `json:"page_url,omitempty"`
	NeedCPU     int      `json:"need_cpu,omitempty"`
	NeedRAMMB   int      `json:"need_ram_mb,omitempty"`
	Prompts     []string `json:"prompts,omitempty"`
	OSOnly      bool     `json:"os_only,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// Present indique un LXC créé par community-scripts.
func (c CS) Present() bool { return c.Script != "" }

// Apt résume l'état apt.
type Apt struct {
	Present        bool     `json:"present"`
	RefreshRC      *int     `json:"refresh_rc,omitempty"`
	RefreshErrors  []string `json:"refresh_errors,omitempty"`
	IndexAgeHours  int      `json:"index_age_h"` // -1 si inconnu
	Total          int      `json:"total"`
	Security       int      `json:"security"`
	SecurityStrict int      `json:"security_strict"`
	// StrictNew : parmi les paquets du mode strict, nouvelles dépendances.
	StrictNew     int  `json:"strict_new"`
	SecurityRepo  bool `json:"security_repo"`
	UpgradeSimple int  `json:"upgrade_simple"`
	// DistTotal : paquets qu'un dist-upgrade installerait (il peut supprimer
	// des paquets) ; PatchWarden ne l'utilise jamais.
	DistTotal int `json:"dist_total"`
	// DistRemove : paquets qu'un dist-upgrade supprimerait.
	DistRemove     int       `json:"dist_remove,omitempty"`
	Packages       []Package `json:"packages"`
	StrictPackages []string  `json:"strict_packages"`
}

// Result est le résultat d'une détection.
type Result struct {
	At             time.Time `json:"at"`
	JobID          string    `json:"job_id"`
	OSID           string    `json:"os_id"`
	OSVersion      string    `json:"os_version"`
	OSPretty       string    `json:"os_pretty"`
	Nproc          int       `json:"nproc"`
	MemMB          int       `json:"mem_mb"`
	RootUsedPct    int       `json:"root_used_pct"`
	RebootRequired bool      `json:"reboot_required"`
	CS             CS        `json:"cs"`
	Apt            Apt       `json:"apt"`
	Docker         bool      `json:"docker"`
	Containers     int       `json:"containers"`
	Apps           []App     `json:"apps,omitempty"`
	Snap           SnapInfo  `json:"snap"`
	// RestartUnits : services systemd encore liés à des bibliothèques
	// remplacées ; RestartProcs : autres processus dans ce cas (hors service).
	RestartUnits []string `json:"restart_units,omitempty"`
	RestartProcs []string `json:"restart_procs,omitempty"`
	// Special : produit particulier installé dans l'invité (pve, pbs, omv) et sa version.
	Special        string `json:"special,omitempty"`
	SpecialVersion string `json:"special_version,omitempty"`
}

// SpecialLabel renvoie le nom lisible du produit particulier.
func (r Result) SpecialLabel() string {
	switch r.Special {
	case "pve":
		return "Proxmox VE"
	case "pbs":
		return "Proxmox Backup Server"
	case "omv":
		return "OpenMediaVault"
	}
	return ""
}

// AppUpdates compte les applis avec une version plus récente.
func (r Result) AppUpdates() int {
	n := 0
	for _, a := range r.Apps {
		if a.UpdateAvailable() {
			n++
		}
	}
	return n
}

// ErrIncomplete : la sortie ne contient pas les marqueurs de début et de fin.
var ErrIncomplete = errors.New("sortie de détection incomplète (marqueurs pw.detect / pw.end absents)")

// Parse interprète les lignes clé=valeur produites par `lxc-detect`.
func Parse(lines []string) (Result, error) {
	r := Result{Apt: Apt{IndexAgeHours: -1}}
	var begin, end bool
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "pw.detect":
			begin = true
		case "pw.end":
			end = true
		case "os.id":
			r.OSID = v
		case "os.version_id":
			r.OSVersion = v
		case "os.pretty":
			r.OSPretty = v
		case "sys.nproc":
			r.Nproc = atoi(v)
		case "sys.mem_mb":
			r.MemMB = atoi(v)
		case "sys.root_used_pct":
			r.RootUsedPct = atoi(v)
		case "sys.reboot_required":
			r.RebootRequired = v == "1"
		case "cs.entry":
			r.CS.Entry = v
		case "cs.script":
			r.CS.Script = v
		case "cs.slug":
			r.CS.Slug = v
		case "cs.base":
			r.CS.Base = v
		case "apt.present":
			r.Apt.Present = v == "1"
		case "apt.refresh_rc":
			n := atoi(v)
			r.Apt.RefreshRC = &n
		case "apt.refresh_err":
			r.Apt.RefreshErrors = append(r.Apt.RefreshErrors, v)
		case "apt.index_age_h":
			r.Apt.IndexAgeHours = atoi(v)
		case "apt.pkg":
			f := strings.Fields(v)
			if len(f) == 4 {
				r.Apt.Packages = append(r.Apt.Packages, Package{Name: f[0], Old: f[1], New: f[2], Security: f[3] == "1"})
			}
		case "apt.total":
			r.Apt.Total = atoi(v)
		case "apt.security":
			r.Apt.Security = atoi(v)
		case "apt.upgrade_simple":
			r.Apt.UpgradeSimple = atoi(v)
		case "apt.dist_total":
			r.Apt.DistTotal = atoi(v)
		case "apt.dist_remove":
			r.Apt.DistRemove = atoi(v)
		case "special.kind":
			r.Special = v
		case "special.version":
			r.SpecialVersion = v
		case "apt.security_repo":
			r.Apt.SecurityRepo = v == "1"
		case "apt.strict_pkg":
			r.Apt.StrictPackages = append(r.Apt.StrictPackages, v)
		case "apt.security_strict":
			r.Apt.SecurityStrict = atoi(v)
		case "restart.unit":
			r.RestartUnits = append(r.RestartUnits, v)
		case "restart.proc":
			r.RestartProcs = append(r.RestartProcs, v)
		case "docker.present":
			r.Docker = v == "1"
		case "docker.containers":
			r.Containers = atoi(v)
		}
	}
	if !begin || !end {
		return r, ErrIncomplete
	}
	r.Apt.reconcileSecurity()
	r.Snap, _ = ParseSnap(lines)
	return r, nil
}

// reconcileSecurity complète le marquage « sécurité » avec la simulation
// stricte. Quand une version plus récente que le correctif existe dans le
// dépôt principal (mise à jour de point Debian), la simulation complète la
// retient et son origine ne mentionne plus le dépôt de sécurité ; le paquet
// a pourtant un correctif de sécurité en attente, visible en mode strict.
// Les paquets que le mode strict installerait sans qu'ils soient déjà
// présents sont de nouvelles dépendances, comptées à part.
func (a *Apt) reconcileSecurity() {
	strict := map[string]bool{}
	for _, n := range a.StrictPackages {
		strict[n] = true
	}
	known := map[string]bool{}
	sec := 0
	for i := range a.Packages {
		p := &a.Packages[i]
		known[p.Name] = true
		if strict[p.Name] && p.Old != "-" {
			p.Security = true
		}
		if p.Security {
			sec++
		}
	}
	a.Security = sec
	a.StrictNew = 0
	for i := range a.Packages {
		if strict[a.Packages[i].Name] && a.Packages[i].Old == "-" {
			a.StrictNew++
		}
	}
	for n := range strict {
		if !known[n] {
			a.StrictNew++
		}
	}
}

// SecurityNotStrict compte les correctifs de sécurité que « Sécurité
// uniquement » ne peut pas installer (dépendance hors dépôt de sécurité).
func (a Apt) SecurityNotStrict() int {
	strict := map[string]bool{}
	for _, n := range a.StrictPackages {
		strict[n] = true
	}
	n := 0
	for _, p := range a.Packages {
		if p.Security && !strict[p.Name] {
			n++
		}
	}
	return n
}

// MajorChange indique un changement du premier numéro de version (2.x → 3.x,
// ou changement de schéma comme release-2.6.1-tag → v26.11.1).
func (a App) MajorChange() bool {
	if !a.UpdateAvailable() {
		return false
	}
	x, y := majorOf(a.Installed), majorOf(a.Latest)
	return x != "" && y != "" && x != y
}

func majorOf(v string) string {
	start := -1
	for i, c := range v {
		if c >= '0' && c <= '9' {
			if start < 0 {
				start = i
			}
		} else if start >= 0 {
			return strings.TrimLeft(v[start:i], "0")
		}
	}
	if start < 0 {
		return ""
	}
	return strings.TrimLeft(v[start:], "0")
}

// ParseVersions interprète la sortie de `lxc-versions`.
func ParseVersions(lines []string) (installed map[string]string, absent map[string]bool) {
	installed, absent = map[string]string{}, map[string]bool{}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if name, ok := strings.CutPrefix(k, "version."); ok {
			installed[name] = v
		} else if name, ok := strings.CutPrefix(k, "version_absent."); ok {
			absent[name] = true
		}
	}
	return installed, absent
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// Store conserve le dernier résultat par invité (clé nœud/vmid), sur disque.
type Store struct {
	path string
	mu   sync.RWMutex
	m    map[string]Result
}

// OpenStore charge le fichier s'il existe.
func OpenStore(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "detections.json"), m: map[string]Result{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.m); err != nil {
		return nil, err
	}
	return s, nil
}

// Get renvoie le dernier résultat d'un invité.
func (s *Store) Get(key string) (Result, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.m[key]
	return r, ok
}

// All renvoie une copie de tous les résultats.
func (s *Store) All() map[string]Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Result, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// Put enregistre un résultat et réécrit le fichier.
func (s *Store) Put(key string, r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	carrySince(s.m[key], &r)
	s.m[key] = r
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.Marshal(s.m)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// carrySince reporte les dates de première apparition depuis le résultat
// précédent : une mise à jour toujours en attente garde sa date d'origine, une
// nouvelle prend la date de la détection.
func carrySince(prev Result, r *Result) {
	pk := map[string]time.Time{}
	for _, p := range prev.Apt.Packages {
		if !p.Since.IsZero() {
			pk[p.Name+"="+p.New] = p.Since
		}
	}
	for i := range r.Apt.Packages {
		p := &r.Apt.Packages[i]
		if t, ok := pk[p.Name+"="+p.New]; ok {
			p.Since = t
		} else if p.Since.IsZero() {
			p.Since = r.At
		}
	}
	ap := map[string]time.Time{}
	for _, a := range prev.Apps {
		if !a.Since.IsZero() {
			ap[a.Name+"="+a.Latest] = a.Since
		}
	}
	for i := range r.Apps {
		a := &r.Apps[i]
		if !a.UpdateAvailable() {
			continue
		}
		if t, ok := ap[a.Name+"="+a.Latest]; ok {
			a.Since = t
		} else if a.Since.IsZero() {
			a.Since = r.At
		}
	}
}

// OldestSecurity renvoie la plus ancienne date d'apparition parmi les
// correctifs de sécurité en attente (zéro s'il n'y en a pas).
func (r Result) OldestSecurity() time.Time {
	var t time.Time
	for _, p := range r.Apt.Packages {
		if p.Security && !p.Since.IsZero() && (t.IsZero() || p.Since.Before(t)) {
			t = p.Since
		}
	}
	return t
}

// NewSince renvoie les correctifs de sécurité et les nouvelles versions
// d'applis apparus à partir de t (nouveautés d'une détection).
func (r Result) NewSince(t time.Time) (security []Package, apps []App) {
	for _, p := range r.Apt.Packages {
		if p.Security && !p.Since.Before(t) {
			security = append(security, p)
		}
	}
	for _, a := range r.Apps {
		if a.UpdateAvailable() && !a.Since.IsZero() && !a.Since.Before(t) {
			apps = append(apps, a)
		}
	}
	return security, apps
}

// systemUnit : service que PatchWarden ne redémarre pas seul (le wrapper les
// exclut aussi) : il faut redémarrer le CT.
func systemUnit(u string) bool {
	switch {
	case u == "dbus.service" || u == "dbus-broker.service" || u == "console-getty.service":
		return true
	}
	for _, p := range []string{"systemd-", "user@", "getty@", "container-getty@", "serial-getty@"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

// RestartableUnits : services que « Redémarrer les services » relancera.
func (r Result) RestartableUnits() []string {
	var out []string
	for _, u := range r.RestartUnits {
		if !systemUnit(u) {
			out = append(out, u)
		}
	}
	return out
}

// RebootAdvised : seul un redémarrage du CT remet tout à neuf (fichier
// reboot-required, service système ou processus hors service concerné).
func (r Result) RebootAdvised() bool {
	if r.RebootRequired || len(r.RestartProcs) > 0 {
		return true
	}
	for _, u := range r.RestartUnits {
		if systemUnit(u) {
			return true
		}
	}
	return false
}

// RestartNeeded : un redémarrage (services ou CT) est utile.
func (r Result) RestartNeeded() bool { return r.RebootAdvised() || len(r.RestartUnits) > 0 }
