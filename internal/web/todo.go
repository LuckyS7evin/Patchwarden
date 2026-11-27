package web

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/LuckyS7evin/patchwarden/internal/detect"
	"github.com/LuckyS7evin/patchwarden/internal/engine"
	"github.com/LuckyS7evin/patchwarden/internal/eol"
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
	"github.com/LuckyS7evin/patchwarden/internal/window"
)

// StaleDetection : au-delà, une détection est signalée comme trop ancienne.
const StaleDetection = 48 * time.Hour

// todoItem est une ligne de « À traiter ».
type todoItem struct {
	Guest inventory.Guest
	Icon  string
	// Sel : valeur de la case de sélection (« nœud/vmid:action ») ; vide si
	// l'invité ne peut pas être mis à jour d'ici.
	Sel string
	// Contenu : paquets (Pkgs, More), application (App) ou texte (Text, Code).
	Pkgs     []string
	More     int
	App      *detect.App
	Text     string
	Code     string
	Tag      string
	TagClass string
	Since    time.Time
	Link     string // page à ouvrir (fiche, onglet utile)
}

type todoGroup struct {
	Key, Title, Why string
	Items           []todoItem
}

// Selectable dit si au moins un élément du groupe peut être sélectionné.
func (g todoGroup) Selectable() bool {
	for _, it := range g.Items {
		if it.Sel != "" {
			return true
		}
	}
	return false
}

// todo : la liste « À traiter » et son résumé.
type todo struct {
	Groups                                []todoGroup
	Count                                 int
	Sec, SecGuests, Versions, Reboots, OK int
}

func guestLink(g inventory.Guest, tab string) string {
	u := fmt.Sprintf("/invites/%s/%d", url.PathEscape(g.Node), g.VMID)
	if tab != "" {
		u += "?onglet=" + tab
	}
	return u
}

// buildTodo classe ce qui attend une action, du plus urgent au moins urgent.
func buildTodo(snap inventory.Snapshot, all map[string]detect.Result, now time.Time, isSelf func(inventory.Guest) bool, osSupport func(detect.Result) eol.Status) todo {
	var t todo
	sec := todoGroup{Key: "securite", Title: "Sécurité", Why: "correctifs en attente, les plus anciens d'abord"}
	major := todoGroup{Key: "majeures", Title: "Versions majeures", Why: "lisez le changelog ; snapshot pré-coché"}
	apps := todoGroup{Key: "applis", Title: "Applications"}
	apt := todoGroup{Key: "paquets", Title: "Autres paquets", Why: "mises à jour apt sans correctif de sécurité"}
	dock := todoGroup{Key: "docker", Title: "Docker", Why: "nouvelles images publiées pour les tags utilisés"}
	restart := todoGroup{Key: "redemarrages", Title: "Redémarrages", Why: "processus qui utilisent encore les anciennes bibliothèques"}
	maint := todoGroup{Key: "entretien", Title: "Entretien"}

	for _, g := range snap.Guests {
		if g.Template || (g.Type != "lxc" && g.Type != "qemu") {
			continue
		}
		det, ok := all[g.Key()]
		running := g.Status == "running" && !g.Stale
		if running && (!ok || now.Sub(det.At) > StaleDetection) {
			it := todoItem{Guest: g, Icon: iconURL(g, nil), Tag: "détection", Link: guestLink(g, "")}
			if ok {
				it.Icon, it.Since = iconURL(g, &det), det.At
				it.Text = "dernière détection trop ancienne : relancez-la"
			} else {
				it.Text = "jamais détecté"
			}
			maint.Items = append(maint.Items, it)
		}
		if !ok {
			continue
		}
		self := isSelf != nil && isSelf(g)
		sel := func(op engine.Op) string {
			if self || !running || g.Critical || det.Special != "" {
				return ""
			}
			return g.Key() + ":" + string(op)
		}
		icon := iconURL(g, &det)
		pending := false

		if det.Apt.Security > 0 {
			pending = true
			var pk []detect.Package
			for _, p := range det.Apt.Packages {
				if p.Security {
					pk = append(pk, p)
				}
			}
			sort.SliceStable(pk, func(i, j int) bool { return pk[i].Since.Before(pk[j].Since) })
			it := todoItem{Guest: g, Icon: icon, Sel: sel(engine.OpSecurity), TagClass: "c", Since: det.OldestSecurity(), Link: guestLink(g, "paquets")}
			for i, p := range pk {
				if i < 3 {
					it.Pkgs = append(it.Pkgs, p.Name)
				}
			}
			it.More = det.Apt.Security - len(it.Pkgs)
			it.Tag = plural(det.Apt.Security, "correctif", "correctifs")
			sec.Items = append(sec.Items, it)
			t.Sec += det.Apt.Security
			t.SecGuests++
		}
		appUpdate := false
		for i := range det.Apps {
			a := det.Apps[i]
			if !a.UpdateAvailable() {
				continue
			}
			pending, appUpdate = true, true
			t.Versions++
			it := todoItem{Guest: g, Icon: icon, Sel: sel(engine.OpFull), App: &a, Since: a.Since, Link: guestLink(g, "")}
			if a.MajorChange() {
				it.Tag, it.TagClass = "majeure", "v"
				major.Items = append(major.Items, it)
			} else {
				it.Tag, it.TagClass = "appli", "w"
				apps.Items = append(apps.Items, it)
			}
		}
		if det.Apt.Total > 0 && det.Apt.Security == 0 && !appUpdate {
			pending = true
			it := todoItem{Guest: g, Icon: icon, Sel: sel(engine.OpFull), Tag: "apt", TagClass: "w", Link: guestLink(g, "paquets")}
			it.Text = plural(det.Apt.Total, "paquet à mettre à jour", "paquets à mettre à jour")
			for _, p := range det.Apt.Packages {
				if it.Since.IsZero() || (!p.Since.IsZero() && p.Since.Before(it.Since)) {
					it.Since = p.Since
				}
			}
			apt.Items = append(apt.Items, it)
		}
		if dockerTodo(&dock, g, det, icon, sel(engine.OpDocker)) {
			pending = true
		}
		if it, ok := newerTagsItem(g, det, icon); ok {
			t.Versions++
			dock.Items = append(dock.Items, it)
		}
		if n := det.DockerInfo.Dangling; n >= 3 {
			maint.Items = append(maint.Items, todoItem{Guest: g, Icon: icon, Text: plural(n, "image Docker sans nom (ancienne version) à nettoyer", "images Docker sans nom (anciennes versions) à nettoyer"), Tag: "Docker", Link: guestLink(g, "docker")})
		}
		for _, w := range det.DockerInfo.Watchtower {
			maint.Items = append(maint.Items, todoItem{Guest: g, Icon: icon, Text: "Watchtower démarré : il met les images à jour en parallèle, arrêtez-le", Code: w, Tag: "Watchtower", TagClass: "w", Link: guestLink(g, "docker")})
		}
		if units := det.RestartableUnits(); len(units) > 0 {
			pending = true
			shown := units
			if len(shown) > 3 {
				shown = shown[:3]
			}
			txt := plural(len(units), "service lié à d'anciennes bibliothèques", "services liés à d'anciennes bibliothèques") + " : " + strings.Join(shown, ", ")
			if len(units) > 3 {
				txt += "…"
			}
			restart.Items = append(restart.Items, todoItem{Guest: g, Icon: icon, Sel: sel(engine.OpServices), Text: txt, Tag: "services", TagClass: "w", Since: det.At, Link: guestLink(g, "")})
		}
		if det.RebootAdvised() {
			pending = true
			t.Reboots++
			txt := "redémarrage requis après une mise à jour"
			if !det.RebootRequired {
				txt = "redémarrage du CT conseillé (processus système liés à d'anciennes bibliothèques)"
			}
			restart.Items = append(restart.Items, todoItem{Guest: g, Icon: icon, Sel: sel(engine.OpReboot), Text: txt, Tag: "redémarrage", TagClass: "w", Since: det.At, Link: guestLink(g, "")})
		}
		for _, sn := range det.Snap.PW {
			maint.Items = append(maint.Items, todoItem{Guest: g, Icon: icon, Text: "snapshot à supprimer une fois la mise à jour validée", Code: sn.Name, Tag: "snapshot", Since: sn.Time, Link: guestLink(g, "snapshots")})
		}
		if osSupport != nil {
			if st := osSupport(det); st.Level == "crit" || st.Level == "warn" {
				cls, tag := "w", "fin de support"
				if st.Level == "crit" {
					cls, tag = "c", "OS sans support"
				}
				maint.Items = append(maint.Items, todoItem{Guest: g, Icon: icon, Text: st.Name + " : " + st.Text, Tag: tag, TagClass: cls, Link: guestLink(g, "")})
			}
		}
		if !pending && running && now.Sub(det.At) <= StaleDetection {
			t.OK++
		}
	}
	bySince := func(items []todoItem) {
		sort.SliceStable(items, func(i, j int) bool {
			a, b := items[i].Since, items[j].Since
			if a.IsZero() != b.IsZero() {
				return !a.IsZero()
			}
			return a.Before(b)
		})
	}
	for _, grp := range []*todoGroup{&sec, &major, &apps, &dock, &apt, &restart, &maint} {
		bySince(grp.Items)
		if len(grp.Items) > 0 {
			t.Groups = append(t.Groups, *grp)
			t.Count += len(grp.Items)
		}
	}
	return t
}

// dockerTodo ajoute les conteneurs à mettre à jour d'un invité : une ligne
// pour ce que PatchWarden sait faire (sélectionnable), une par groupe à
// traiter à la main.
func dockerTodo(grp *todoGroup, g inventory.Guest, det detect.Result, icon, sel string) bool {
	d := det.DockerInfo
	var names []string
	var since time.Time
	n := 0
	found := false
	for _, gr := range d.Groups {
		if gr.Updates == 0 {
			continue
		}
		found = true
		var imgs []string
		first := time.Time{}
		for _, cn := range gr.Containers {
			c, _ := d.Container(cn)
			if c.Running() && c.UpdateAvailable() {
				imgs = append(imgs, c.Name)
				if !c.Since.IsZero() && (first.IsZero() || c.Since.Before(first)) {
					first = c.Since
				}
			}
		}
		if !gr.Updatable() {
			grp.Items = append(grp.Items, todoItem{Guest: g, Icon: icon, Text: gr.Label() + " : " + gr.Blocker, Code: strings.Join(imgs, ", "), Tag: "à la main", Since: first, Link: guestLink(g, "docker")})
			continue
		}
		n += gr.Updates
		names = append(names, gr.Name)
		if !first.IsZero() && (since.IsZero() || first.Before(since)) {
			since = first
		}
	}
	if n > 0 {
		grp.Items = append(grp.Items, todoItem{Guest: g, Icon: icon, Sel: sel, Text: plural(len(names), "stack ou projet", "stacks ou projets") + " : " + strings.Join(names, ", "),
			Tag: plural(n, "image", "images"), TagClass: "w", Since: since, Link: guestLink(g, "docker")})
	}
	return found
}

// newerTagsItem résume, en une ligne par invité, les conteneurs dont une
// version plus récente est publiée sous un autre tag (information : le tag se
// change à la main). Le détail est dans l'onglet Docker.
func newerTagsItem(g inventory.Guest, det detect.Result, icon string) (todoItem, bool) {
	var cs []detect.Container
	for _, c := range det.DockerInfo.List {
		if c.NewTag != "" {
			cs = append(cs, c)
		}
	}
	it := todoItem{Guest: g, Icon: icon, Tag: "autre tag", TagClass: "v", Link: guestLink(g, "docker")}
	switch len(cs) {
	case 0:
		return it, false
	case 1:
		c := cs[0]
		it.App = &detect.App{Name: c.Name, Installed: c.Tag(), Latest: c.NewTag, ChangelogURL: c.ChangelogURL}
		return it, true
	}
	names := make([]string, 0, 3)
	for _, c := range cs[:min(3, len(cs))] {
		names = append(names, c.Name)
	}
	it.Text = fmt.Sprintf("%d conteneurs : version plus récente sous un autre tag (%s", len(cs), strings.Join(names, ", "))
	if len(cs) > 3 {
		it.Text += "…"
	}
	it.Text += ")"
	return it, true
}

func plural(n int, one, many string) string {
	if n > 1 {
		return fmt.Sprintf("%d %s", n, many)
	}
	return fmt.Sprintf("%d %s", n, one)
}

type todoData struct {
	base
	// Sécurité automatique : prochaine exécution et invités concernés.
	AutoNext  string
	AutoCount int
	Todo      todo
	Tags      []string // tags des invités présents dans la liste
	Tag       string   // filtre courant
	Activity  []jobs.Job
	Loaded    bool
	Detected  bool // au moins une détection
	Error     string
	Selection bool // au moins un élément sélectionnable
}

func (s *Server) todoPage(w http.ResponseWriter, r *http.Request, se *session) {
	snap, _ := s.inv.Current()
	s.deps.Engine.SyncSnapshots(snap.Guests)
	all := s.allDetections()
	d := todoData{
		base:     s.base("À traiter", "traiter", se),
		Todo:     buildTodo(snap, all, s.now(), s.isSelf, s.osSupport),
		Loaded:   !snap.FetchedAt.IsZero(),
		Detected: len(all) > 0,
		Error:    r.URL.Query().Get("erreur"),
		Tag:      r.URL.Query().Get("tag"),
	}
	tags := map[string]bool{}
	var groups []todoGroup
	for _, g := range d.Todo.Groups {
		var items []todoItem
		for _, it := range g.Items {
			for _, t := range it.Guest.Tags {
				if !strings.EqualFold(t, s.cfg.Policy.CommunityScriptTag) {
					tags[t] = true
				}
			}
			if d.Tag == "" || hasTag(it.Guest.Tags, d.Tag) {
				items = append(items, it)
			}
		}
		if len(items) > 0 {
			g.Items = items
			groups = append(groups, g)
		}
	}
	d.Todo.Groups = groups
	if t := s.deps.Engine.NextAuto(s.now()); !t.IsZero() {
		d.AutoNext, d.AutoCount = window.FormatTime(t), len(s.deps.Engine.AutoCandidates())
	}
	for t := range tags {
		d.Tags = append(d.Tags, t)
	}
	sort.Strings(d.Tags)
	if s.deps.Jobs != nil {
		d.Activity = s.deps.Jobs.List("", 8)
	}
	for _, g := range d.Todo.Groups {
		for _, it := range g.Items {
			if it.Sel != "" {
				d.Selection = true
			}
		}
	}
	s.render(w, "traiter", http.StatusOK, d)
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func (s *Server) osSupport(r detect.Result) eol.Status {
	if s.deps.Engine == nil {
		return eol.Status{}
	}
	return s.deps.Engine.OSSupport(r)
}
