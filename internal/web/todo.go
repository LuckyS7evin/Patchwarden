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
	"github.com/LuckyS7evin/patchwarden/internal/inventory"
	"github.com/LuckyS7evin/patchwarden/internal/jobs"
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
func buildTodo(snap inventory.Snapshot, all map[string]detect.Result, now time.Time, isSelf func(inventory.Guest) bool) todo {
	var t todo
	sec := todoGroup{Key: "securite", Title: "Sécurité", Why: "correctifs en attente, les plus anciens d'abord"}
	major := todoGroup{Key: "majeures", Title: "Versions majeures", Why: "lisez le changelog ; snapshot pré-coché"}
	apps := todoGroup{Key: "applis", Title: "Applications"}
	apt := todoGroup{Key: "paquets", Title: "Autres paquets", Why: "mises à jour apt sans correctif de sécurité"}
	maint := todoGroup{Key: "entretien", Title: "Entretien"}

	for _, g := range snap.Guests {
		if g.Template || g.Type != "lxc" {
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
		sel := func(a engine.Action) string {
			if self || !running {
				return ""
			}
			return g.Key() + ":" + string(a)
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
			it := todoItem{Guest: g, Icon: icon, Sel: sel(engine.ActSecurity), TagClass: "c", Since: det.OldestSecurity(), Link: guestLink(g, "paquets")}
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
			it := todoItem{Guest: g, Icon: icon, Sel: sel(engine.ActFull), App: &a, Since: a.Since, Link: guestLink(g, "")}
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
			it := todoItem{Guest: g, Icon: icon, Sel: sel(engine.ActFull), Tag: "apt", TagClass: "w", Link: guestLink(g, "paquets")}
			it.Text = plural(det.Apt.Total, "paquet à mettre à jour", "paquets à mettre à jour")
			for _, p := range det.Apt.Packages {
				if it.Since.IsZero() || (!p.Since.IsZero() && p.Since.Before(it.Since)) {
					it.Since = p.Since
				}
			}
			apt.Items = append(apt.Items, it)
		}
		if det.RebootRequired {
			pending = true
			t.Reboots++
			maint.Items = append(maint.Items, todoItem{Guest: g, Icon: icon, Text: "redémarrage requis après une mise à jour", Tag: "redémarrage", TagClass: "w", Since: det.At, Link: guestLink(g, "")})
		}
		for _, sn := range det.Snap.PW {
			maint.Items = append(maint.Items, todoItem{Guest: g, Icon: icon, Text: "snapshot à supprimer une fois la mise à jour validée", Code: sn.Name, Tag: "snapshot", Since: sn.Time, Link: guestLink(g, "snapshots")})
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
	for _, grp := range []*todoGroup{&sec, &major, &apps, &apt, &maint} {
		bySince(grp.Items)
		if len(grp.Items) > 0 {
			t.Groups = append(t.Groups, *grp)
			t.Count += len(grp.Items)
		}
	}
	return t
}

func plural(n int, one, many string) string {
	if n > 1 {
		return fmt.Sprintf("%d %s", n, many)
	}
	return fmt.Sprintf("%d %s", n, one)
}

type todoData struct {
	base
	Todo      todo
	Activity  []jobs.Job
	Loaded    bool
	Detected  bool // au moins une détection
	Error     string
	Selection bool // au moins un élément sélectionnable
}

func (s *Server) todoPage(w http.ResponseWriter, r *http.Request, se *session) {
	snap, _ := s.inv.Current()
	all := s.allDetections()
	d := todoData{
		base:     s.base("À traiter", "traiter", se),
		Todo:     buildTodo(snap, all, s.now(), s.isSelf),
		Loaded:   !snap.FetchedAt.IsZero(),
		Detected: len(all) > 0,
		Error:    r.URL.Query().Get("erreur"),
	}
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

// batchSimulate lance la simulation de chaque élément sélectionné. Les lots
// réels (avec confirmation) arrivent au jalon 6.
func (s *Server) batchSimulate(w http.ResponseWriter, r *http.Request, se *session) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formulaire invalide", http.StatusBadRequest)
		return
	}
	snap, _ := s.inv.Current()
	byKey := map[string]inventory.Guest{}
	for _, g := range snap.Guests {
		byKey[g.Key()] = g
	}
	// Un invité choisi pour « sécurité » et « tout » n'est simulé qu'une fois,
	// en « tout mettre à jour ».
	want := map[string]engine.Action{}
	var order []string
	for _, v := range r.PostForm["sel"] {
		key, act, ok := strings.Cut(v, ":")
		a, err := engine.ParseAction(act)
		if !ok || err != nil {
			continue
		}
		if prev, seen := want[key]; !seen {
			order = append(order, key)
			want[key] = a
		} else if prev == engine.ActSecurity && a == engine.ActFull {
			want[key] = a
		}
	}
	started, skipped := 0, 0
	for _, key := range order {
		g, ok := byKey[key]
		if !ok {
			skipped++
			continue
		}
		if _, err := s.deps.Engine.Execute(g, want[key], true, se.user, false, "", false); err != nil {
			skipped++
			continue
		}
		started++
	}
	s.log.Info("simulation par lot", "lancées", started, "ignorées", skipped, "par", se.user)
	if started == 0 && skipped == 0 {
		http.Redirect(w, r, "/?erreur="+url.QueryEscape("aucun invité sélectionné"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/taches?simulations=%d&ignores=%d", started, skipped), http.StatusSeeOther)
}
